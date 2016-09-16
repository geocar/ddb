-module(aws).

-export([signature_version_4_signing/6]).

-export([iso_8601_basic_format/1]).

-include_lib("eunit/include/eunit.hrl").

-export([endpoint/2, credentials/1, credentials/2]).

-record(credentials, {
  access_key_id     = <<"WHATEVER">> :: binary(),
  secret_access_key = <<"WHATEVER">> :: binary(),

  token     :: binary(),
  imds_role :: binary(),
  iam       :: pid()
}).

-spec endpoint(binary(), binary()) -> binary().
endpoint(Service, Region) ->
    <<Service/binary, $., Region/binary, $., "amazonaws.com">>.


-spec credentials(binary() | #credentials{} | {term(),{binary(),binary(),binary(),binary()}}) -> #credentials{}.
credentials(Name) when is_binary(Name) -> credentials(#credentials{ imds_role = Name });
credentials(Credentials = #credentials{ iam = Pid }) when is_pid(Pid) ->
  receive
    {Pid, iamChange, {Access,Secret,Token,Name}} ->
			Credentials#credentials{ access_key_id = Access, secret_access_key = Secret, token = Token, imds_role = Name }
  after 0 ->
    Credentials
  end;
credentials(Credentials = #credentials{ imds_role = Name } ) ->
  Pid = spawn_link(imds, iam, [self(), Name]),
  receive
    {Pid , iamChange, {Access,Secret,Token,Name}} ->
			Credentials#credentials{ access_key_id = Access, secret_access_key = Secret, token = Token, iam = Pid }
  end.

credentials(AccessKeyId, SecretAccessKey) ->
  #credentials{
    access_key_id = AccessKeyId,
    secret_access_key = SecretAccessKey
  }.

hmacsha256(Key, Sign) ->
  case erlang:function_exported(crypto, sha256_mac_n, 3) of
    true  -> crypto:sha256_mac_n(Key, Sign, 32);
    false -> crypto:hmac(sha256, Key, Sign)
  end.

sha256(Text) ->
  case erlang:function_exported(crypto, sha256, 1) of
    true -> crypto:sha256(Text);
    false -> crypto:hash(sha256, Text)
  end.

%% 20110909T233600Z
-spec iso_8601_basic_format(erlang:timestamp()) -> binary().
iso_8601_basic_format(Timestamp) ->
    {{Year, Month, Day}, {Hour, Min, Sec}} = calendar:now_to_universal_time(Timestamp),
    list_to_binary(io_lib:format("~4.10.0B~2.10.0B~2.10.0BT~2.10.0B~2.10.0B~2.10.0BZ",
                                 [Year, Month, Day, Hour, Min, Sec])).

headers(DateTime, #credentials{ token = Token }, Headers) when is_binary(Token) ->
  [{<<"x-amz-security-token">>, Token}|headers(DateTime, [], Headers)];
headers(DateTime, _, Headers) -> [{<<"x-amz-date">>, DateTime}|Headers].

-spec signature_version_4_signing(binary(), #credentials{}, [{binary(), binary()}], binary(), binary(), binary()) -> [{binary(), binary()}]. 
signature_version_4_signing(DateTime, Credentials, Headers, Payload, Service, Region) ->
    #credentials{ access_key_id = AccessKeyId, secret_access_key = SecretAccessKey } = Credentials,

    ExtraHeaders = headers(DateTime, Credentials, Headers),
    {CanonicalHeaders, SignedHeaders} = canonical_headers(ExtraHeaders),
    Request = canonical_request(<<"POST">>, <<$/>>, <<>>, CanonicalHeaders, SignedHeaders, Payload),
    CredentialScope = credential_scope(DateTime, Region, Service),


    ToSign = to_sign(DateTime, CredentialScope, Request),
    SigningKey = signing_key(SecretAccessKey, DateTime, Region, Service),
    Signature = base16(hmacsha256(SigningKey, ToSign)),
    Authorization = authorization(AccessKeyId, CredentialScope, SignedHeaders, Signature),
    [{<<"Authorization">>, Authorization}|ExtraHeaders].


to_sign(Datetime, CredentialScope, Request) ->
    <<"AWS4-HMAC-SHA256", $\n,
      Datetime/binary, $\n,
      CredentialScope/binary, $\n,
      (hash_encode(Request))/binary>>.


hash_encode(Value) ->
    base16(sha256(Value)).


base16(Value) -> bin_to_hex:bin_to_hex(Value).


-spec credential_scope(binary(), binary(), binary()) -> binary().
credential_scope(DateTime, Region, Service) ->
    Date = datetime_to_date(DateTime),
    <<Date/binary, $/, Region/binary, $/, Service/binary, $/, "aws4_request">>.


-spec canonical_request(binary(), binary(), binary(), binary(), binary(), binary()) -> binary().
canonical_request(Method, CanonicalURI, CanonicalQueryString, CanonicalHeaders, SignedHeaders, Payload) ->
    <<Method/binary, $\n,
      CanonicalURI/binary, $\n,
      CanonicalQueryString/binary, $\n,
      CanonicalHeaders/binary, $\n,
      SignedHeaders/binary, $\n,
      (hash_encode(Payload))/binary>>.


%% 20110909T233600Z -> 20110909
-spec datetime_to_date(binary()) -> binary().
datetime_to_date(DateTime) ->
    binary:part(DateTime, {0, 8}).


signing_key(SecretAccessKey, DateTime, Region, Service) ->
    Date = datetime_to_date(DateTime),
    %% Region = <<"ap-northeast-1">>,
    %% Service = <<"amazondb">>,

    %% XXX(nakai): KSecret はあえて変数へ代入してる
    KSecret = SecretAccessKey,
    KDate = hmacsha256(<<"AWS4", KSecret/binary>>, Date),
    KRegion = hmacsha256(KDate, Region),
    KService = hmacsha256(KRegion, Service),
    %% XXX(nakai): KSigning はあえて変数へ代入してる
    KSigning = hmacsha256(KService, <<"aws4_request">>),
    KSigning.



trimall(Value) ->
    TrimedValue = re:replace(Value, <<"(^\\s+)|(\\s+$)">>, <<>>, [global, {return, binary}]),
    %% XXX(nakai): "" で囲まれているっぽい文字があったら、Trim で終わらせる
    case re:run(TrimedValue, <<"\"">>) of
        nomatch ->
            re:replace(TrimedValue, <<"(\\s+)">>, <<"\s">>, [global, {return, binary}]);
        _ ->
            TrimedValue
    end.

%
to_lower(B) -> << << (string:to_lower(C)) >> || << C >> <= B >>.

%% content-length;content-type;host;user-agent;x-amz-content-sha256;x-amz-date;x-amz-target
-spec canonical_headers([{binary(), binary()}]) -> {binary(), binary()}.
canonical_headers(Headers) ->
    Normalized = [ {to_lower(Name), trimall(Value)} || {Name, Value} <- Headers],
    Sorted = lists:keysort(1, Normalized),
    Canonical = << <<Name/binary, $:, Value/binary, $\n>> || {Name, Value} <- Sorted >>,
    %% XXX(nakai): 効率悪い
    Signed0 = << <<Name/binary, $;>> || {Name, _Value} <- Sorted >>,
    Signed = binary:part(Signed0, {0, byte_size(Signed0) - 1}),
    {Canonical, Signed}.


authorization(AccessKeyId, CredentialScope, SignedHeaders, Signature) ->
    %% XXX(nakai): Credential はあえて変数へ代入している
    Credential = <<AccessKeyId/binary, $/, CredentialScope/binary>>,
    <<"AWS4-HMAC-SHA256 ",
      "Credential=", Credential/binary, $,,
      "SignedHeaders=", SignedHeaders/binary, $,,
      "Signature=", Signature/binary>>.


-ifdef(TEST).

signing_key_test() ->
    %% http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY">>,
    DateTime = <<"20110909T000000Z">>,
    Region = <<"us-east-1">>,
    Service = <<"iam">>,
    SigningKey = <<152,241,216,137,254,196,244,66,26,220,82,43,171,12,225,248,
                   46,105,41,194,98,237,21,229,169,76,144,239,209,227,176,231>>,
    ?assertEqual(SigningKey, signing_key(SecretAccessKey, DateTime, Region, Service)),

    ok.


canonical_headers_test() ->
    %% http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    Original = [{<<"host">>, <<"iam.amazonaws.com">>},
                {<<"Content-type">>, <<"application/x-www-form-urlencoded; charset=utf-8">>},
                {<<"My-header1">>, <<"    a   b   c ">>},
                {<<"x-amz-date">>, <<"20120228T030031Z">>},
                {<<"My-Header2">>, <<"    \"a   b   c\"">>}],

    Canonical = <<"content-type:application/x-www-form-urlencoded; charset=utf-8\n",
                  "host:iam.amazonaws.com\n",
                  "my-header1:a b c\n",
                  "my-header2:\"a   b   c\"\n",
                  "x-amz-date:20120228T030031Z\n">>,

    Signed = <<"content-type;host;my-header1;my-header2;x-amz-date">>,
    ?assertEqual({Canonical, Signed}, canonical_headers(Original)),
    ok.


signature_test() ->
    %% http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

    Region = <<"us-east-1">>,
    Service = <<"iam">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY">>,

    DateTime = <<"20110909T233600Z">>,

    Headers = [{<<"content-type">>, <<"application/x-www-form-urlencoded; charset=utf-8">>},
               {<<"host">>, <<"iam.amazonaws.com">>},
               {<<"x-amz-date">>, DateTime}],
    {CanonicalHeaders, SignedHeaders} = canonical_headers(Headers),
    
    ?assertEqual(<<"content-type;host;x-amz-date">>, SignedHeaders),

    Payload = <<"Action=ListUsers&Version=2010-05-08">>,

    Request = canonical_request(<<"POST">>, <<$/>>, <<>>, CanonicalHeaders, SignedHeaders, Payload),

    CredentialScope = credential_scope(DateTime, Region, Service),

    SigningKey = signing_key(SecretAccessKey, DateTime, Region, Service),

    ToSign = to_sign(DateTime, CredentialScope, Request),

    Signature = base16(hmacsha256(SigningKey, ToSign)),

    ?assertEqual(<<"ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c">>, Signature),

    ok.

signature_version_4_signing_test() ->
    %% http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

    AccessKeyId = <<"AKIDEXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY">>,

    Service = <<"iam">>,
    Region = <<"us-east-1">>,

    DateTime = <<"20110909T233600Z">>,

    Headers = [{<<"host">>, <<"iam.amazonaws.com">>},
               {<<"Content-type">>, <<"application/x-www-form-urlencoded; charset=utf-8">>}],

    Payload = <<"Action=ListUsers&Version=2010-05-08">>,

    Headers1 = signature_version_4_signing(DateTime, credentials(AccessKeyId, SecretAccessKey), Headers, Payload, Service, Region),

    ?assertEqual(<<"AWS4-HMAC-SHA256 ",
                   "Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request,",
                   "SignedHeaders=content-type;host;x-amz-date,",
                   "Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c">>,
                 proplists:get_value(<<"Authorization">>, Headers1)),

    ok.

-endif.
