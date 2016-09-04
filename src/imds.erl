-module(imds).
-export([region/0, iam/2]).

-define(OVERLAPIAM, 3600).

text(Path) ->
  {ok,200,_,ClientRef}=hackney:get(<<"http://169.254.169.254/latest/", Path/binary>>, []),
  {ok, Body} = hackney:body(ClientRef),
  Body.
json(Path) -> jsone:decode(text(Path), [{object_format,proplist}]).

region() -> proplists:get_value(<<"region">>, json(<<"dynamic/instance-identity/document">>)).

iam(P, Name) ->
  Info = json(<<"meta-data/iam/security-credentials/", Name/binary>>) ++ [{<<"Name">>, Name}],
  Expiration = proplists:get_value(<<"Expiration">>, Info),
  Expires = case is_binary(Expiration) of true -> calendar:datetime_to_gregorian_seconds(iso8601:parse(Expiration)); _ -> undefined end,
  P!{self(), {proplists:get_value(<<"AccessKeyId">>, Info),
    proplists:get_value(<<"SecretAccessKey">>, Info),
    proplists:get_value(<<"Token">>, Info),
    proplists:get_value(<<"Name">>, Info)}},
  Now = calendar:datetime_to_gregorian_seconds(erlang:universaltime()),
  timer:sleep((Expires - Now - round(?OVERLAPIAM * 0.9)) * 1000),
  iam(P, Name).
