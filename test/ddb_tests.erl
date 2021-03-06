-module(ddb_tests).

-include_lib("eunit/include/eunit.hrl").

%% connection_test() ->
%% 
%%     AccessKeyId = list_to_binary(os:getenv("AWS_ACCESS_KEY_ID")),
%%     SecretAccessKey = list_to_binary(os:getenv("AWS_SECRET_ACCESS_KEY")),
%%     Region = <<"ap-northeast-1">>,
%%     IsSecure = true,
%% 
%%     application:start(crypto),
%%     application:start(asn1),
%%     application:start(public_key),
%%     application:start(ssl),
%%     application:start(mimetypes),
%%     application:start(hackney_lib),
%%     application:start(hackney),
%% 
%%     C = ddb:connection(AccessKeyId, SecretAccessKey, Region, IsSecure),
%%     ddb:put_item(C, <<"users">>, [{<<"user_id">>, <<"USER-ID">>},
%%                                   {<<"password">>, <<"PASSWORD">>},
%%                                   {<<"gender">>, <<"GENDER">>}]),
%%     ddb:update_item(C, <<"users">>, <<"user_id">>, <<"USER-ID">>, [{<<"gender">>, <<"PUT">>, <<"gender">>}]),
%%     ddb:get_item(C, <<"users">>, <<"user_id">>, <<"USER-ID">>),
%% 
%%     application:stop(crypto),
%%     application:stop(asn1),
%%     application:stop(public_key),
%%     application:stop(ssl),
%%     application:stop(mimetypes),
%%     application:stop(hackney_lib),
%%     application:stop(hackney),
%% 
%%     ok.


connection_local_test_() ->
    {setup,
     fun() ->
	     application:start(crypto),
	     application:start(asn1),
	     application:start(public_key),
	     application:start(ssl),
	     application:start(mimetypes),
	     application:start(hackney_lib),
	     application:start(hackney),
	     hackney:start()
     end,
     fun(_) ->
	     hackney:stop(),
	     application:stop(crypto),
	     application:stop(asn1),
	     application:stop(public_key),
	     application:stop(ssl),
	     application:stop(mimetypes),
	     application:stop(hackney_lib),
	     application:stop(hackney)
     end,
     [
      fun success/0
     ]
    }.


success() ->
    C = ddb:connection_local(),
    ?assertEqual([],
		 ddb:list_tables(C)),
    ?assertEqual(ok,
                 ddb:create_table(C, <<"users">>, <<"user_id">>, <<"HASH">>)),
    ?assertEqual(ok,
                 ddb:put_item(C, <<"users">>, [{<<"user_id">>, <<"USER-ID">>},
                                               {<<"password">>, <<"PASSWORD">>},
                                               {<<"gender">>, 1}])),
    ?assertMatch({error, {_, _}},
                 ddb:put_item(C, <<"users">>, [{<<"user_id">>, <<"USER-ID">>},
                                               {<<"password">>, <<"PASSWORD">>},
                                               {<<"gender">>, 1}])),
    ?assertEqual(lists:sort([{<<"gender">>, 1},
                  {<<"user_id">>, <<"USER-ID">>},
                  {<<"password">>, <<"PASSWORD">>}]),
                 lists:sort(ddb:get_item(C, <<"users">>, <<"user_id">>, <<"USER-ID">>))),
    ?assertEqual(ok,
                 ddb:update_item(C, <<"users">>, <<"user_id">>, <<"USER-ID">>,
                                 [{<<"gender">>, <<"PUT">>, 0},
                                  {<<"password">>, <<"PUT">>, <<"PASS">>}])),
    ?assertEqual(lists:sort([{<<"gender">>, 0},
                  {<<"user_id">>, <<"USER-ID">>},
                  {<<"password">>, <<"PASS">>}]),
                 lists:sort(ddb:get_item(C, <<"users">>, <<"user_id">>, <<"USER-ID">>))),
    ?assertEqual(ok,
                 ddb:delete_item(C, <<"users">>, <<"user_id">>, <<"USER-ID">>)),
    ?assertEqual(not_found,
                 ddb:get_item(C, <<"users">>, <<"user_id">>, <<"USER-ID">>)),
    ?assertEqual(ok,
                 ddb:batch_write_item(C, <<"users">>, [
                                      [{<<"user_id">>, <<"wat">>}, {<<"password">>, <<"dude">>}],
                                      [{<<"user_id">>, <<"for">>}, {<<"password">>, <<"cows">>}]
                 ])),
    ?assertEqual(lists:sort([[{<<"user_id">>,<<"for">>},{<<"password">>,<<"cows">>}],[{<<"user_id">>,<<"wat">>},{<<"password">>,<<"dude">>}]]),
                 lists:sort(ddb:scan(C,<<"users">>))),
    ?assertEqual(ok,
		 ddb:delete_table(C, <<"users">>)),

    ok.
