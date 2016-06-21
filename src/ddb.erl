-module(ddb).

-export([connection/1, connection/4]).
-export([connection_local/0, connection_local/2]).

-export([create_table/4, create_table/3]).
-export([delete_item/4, delete_item/3]).
-export([delete_table/2]).
-export([get_item/3, get_item/4, get_item/6]).
-export([list_tables/1]).
-export([put_item/3]).
-export([update_item/5, update_item/4]).
-export([scan/2, scan/3, scan/4, scan/6]).

-export_type([config/0]).

-include_lib("eunit/include/eunit.hrl").

-define(SERVICE, <<"dynamodb">>).

-record(ddb_config, {
  credentials :: aws:credentials(),
          is_secure = true :: boolean(),
          endpoint :: binary(),
          service = ?SERVICE :: binary(),
          region :: binary()
         }).

-type config() :: #ddb_config{}.

%% jsonx -> ejson(jiffy)
%je([{K,V}])           -> {[{K,je(V)}]};
%je([{K,V}|T])         -> {R}=je(T), {[{K,je(V)}]++R};
%je(A) when is_list(A) -> lists:map(fun je/1, A);
%je({A})               -> {je(A)};
%je(X)                 -> X.
%
%json_encode(A) -> jiffy:encode(je(A)).


%% ejson -> jsonx
%jd({[{K,V}]})   -> [{K,jd(V)}];
%jd({[{K,V}|T]}) -> [{K,jd(V)}] ++ jd({T});
%jd(A) when is_list(A) -> lists:map(fun jd/1, A);
%jd(X)           -> X.
%
%json_decode(A) -> jd(jiffy:decode(A)).


json_encode(A) -> jsone:encode(A).
json_decode(A) -> jsone:decode(A, [{object_format,proplist}]).

% json_encode(A) -> jsonx:encode(A).
% json_decode(A) -> jsonx:decode(A, [{format,proplist}]).


%% http://docs.aws.amazon.com/general/latest/gr/rande.html#ddb_region

%% XXX(nakai): サービスの扱いをどうするか考える

-spec connection(#ddb_config{} | binary()) -> #ddb_config{}.

connection(Config = #ddb_config{credentials = Credentials}) ->
  Config#ddb_config{ credentials = aws:credentials(Credentials) };

connection(IAMName) ->
    Region = imds:region(),
    #ddb_config{
      credentials = aws:credentials(IAMName),
      region = Region,
      is_secure = false,
      endpoint = aws:endpoint(?SERVICE, Region)
    }.

-spec connection(binary(), binary(), binary(), boolean()) -> #ddb_config{}.
connection(AccessKeyId, SecretAccessKey, Region, IsSecure) ->
    #ddb_config{
       credentials = aws:credentials(AccessKeyId, SecretAccessKey),
       region = Region,
       is_secure = IsSecure,
       endpoint = aws:endpoint(?SERVICE, Region)
      }.


connection_local() ->
    connection_local(<<"127.0.0.1">>, 8000).

connection_local(Host, Port) ->
    #ddb_config{
       credentials = aws:credentials(<<"whatever">>, <<"whatever">>),
       endpoint = <<Host/binary, $:, (integer_to_binary(Port))/binary>>,
       region = <<"ap-northeast-1">>,
       is_secure = false
      }.


-spec put_item(#ddb_config{}, binary(), [{binary(), binary()}]) -> ok.
put_item(Config, TableName, Item) ->
    Target = x_amz_target(put_item),
    Payload = put_item_payload(TableName, Item),
    case post(Config, Target, Payload) of
        {ok, _Json} ->
            ok;
        {error, Reason} ->
            ?debugVal(Reason),
            {error, Reason}
    end.


put_item_payload(TableName, Item) ->
    F = fun({Name, _Value}) ->
           %% FIXME(nakai): 上書き禁止を固定している
           {Name, [{<<"Exists">>, false}]}
        end,
    Expected = lists:map(F, Item),
    Json = [{<<"TableName">>, TableName},
            {<<"Expected">>, Expected},
            {<<"Item">>, typed_item(Item)}],
    json_encode(Json).


%% テーブルの主キーはhashタイプ(1要素主キー)と、hash-and-rangeタイプ(2要素で主キー)があり得る
%% http://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html
-spec get_item(#ddb_config{}, binary(), binary()) -> not_found | [{binary(), binary()}].
get_item(Config, TableName, KV) ->
    Target = x_amz_target(get_item),
    Payload = get_item_payload(TableName, KV),
    get_item_request(Config, Target, Payload).

-spec get_item(#ddb_config{}, binary(), binary(), binary()) -> not_found | [{binary(), binary()}].
get_item(Config, TableName, Key, Value) ->
    Target = x_amz_target(get_item),
    Payload = get_item_payload(TableName, {Key, Value}),
    get_item_request(Config, Target, Payload).

-spec get_item(#ddb_config{}, binary(), binary(), binary(), binary(), binary()) -> not_found | [{binary(), binary()}].
get_item(Config, TableName, HashKey, HashValue, RangeKey, RangeValue) ->
    Target = x_amz_target(get_item),
    Payload = get_item_payload(TableName, HashKey, HashValue, RangeKey, RangeValue),
    get_item_request(Config, Target, Payload).


get_item_request(Config, Target, Payload) ->
    case post(Config, Target, Payload) of
        {ok, []}   -> not_found; % jsonx
        {ok, {[]}} -> not_found; % jiffy
        {ok, [{}]} -> not_found; % jsone
        {ok, Json} ->
            %% XXX(nakai): Item はあえて出している
            cast_item(proplists:get_value(<<"Item">>, Json));
        {error, Reason} ->
            ?debugVal(Reason),
            error(Reason)
    end.


get_item_payload(TableName, KV) ->
    %% http://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html
    Json = [{<<"TableName">>, TableName},
            {<<"Key">>, typed_item(KV)},
            {<<"ConsistentRead">>, true}],
    json_encode(Json).

get_item_payload(TableName, HashKey, HashValue, RangeKey, RangeValue) ->
    %% http://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html
    Json = [{<<"TableName">>, TableName},
            {<<"Key">>, typed_item([{HashKey, HashValue}, {RangeKey, RangeValue}])},
            {<<"ConsistentRead">>, true}],
    json_encode(Json).


typed_item(Item) when is_tuple(Item) ->
    [typed_attribute(Item)];
typed_item(Item) when is_list(Item) ->
    lists:map(fun typed_attribute/1, Item).


typed_attribute({Key, Value}) ->
    {Key, typed_value(Value)}.


typed_value(Value) when is_tuple(Value) ->
    [Value];
typed_value([{Type,Value}]) ->
    [{Type,Value}];
typed_value(Value) when is_binary(Value) ->
    [{<<"S">>, Value}];
typed_value(Value) when is_atom(Value) ->
    [{<<"S">>, list_to_binary(atom_to_list(Value))}];
typed_value(Value) when is_list(Value) ->
    [{<<"S">>, list_to_binary(Value)}];
typed_value(Value) when is_integer(Value) ->
    [{<<"N">>, integer_to_binary(Value)}].


-spec list_tables(#ddb_config{}) -> [binary()].
list_tables(Config) ->
    Target = x_amz_target(list_tables),
    Payload = <<"{}">>,
    case post(Config, Target, Payload) of
        {ok, Json} ->
            proplists:get_value(<<"TableNames">>, Json);
        {error, Reason} ->
            ?debugVal(Reason),
            error(Reason)
    end.


create_table(Config, TableName, Keys) ->
    Target = x_amz_target(create_table),
    Payload = create_table_payload(TableName, Keys),
    case post(Config, Target, Payload) of
        {ok, _Json} ->
            ok;
        {error, Reason} ->
            ?debugVal(Reason),
            error(Reason)
    end.
create_table(Config, TableName, AttributeName, KeyType) ->
    create_table(Config, TableName, [{AttributeName, <<"S">>, KeyType}]).

attribute_definition_payload({AttributeName,AttributeType,_}) ->
    [
        {<<"AttributeName">>, AttributeName},
        {<<"AttributeType">>, AttributeType}
    ].

key_schema_payload({AttributeName,_,KeyType}) ->
    [
        {<<"AttributeName">>, AttributeName},
        {<<"KeyType">>, KeyType}
    ].

%% KeyType HASH RANGE
create_table_payload(TableName, List) ->
    %% http://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html
    Json = [
        {
            <<"TableName">>, TableName
        },
        {
            <<"AttributeDefinitions">>,
            lists:map(fun attribute_definition_payload/1, List)
        },
        {
            <<"ProvisionedThroughput">>,
            [
                {<<"ReadCapacityUnits">>, 1},
                {<<"WriteCapacityUnits">>, 1}
            ]
        },
        {
            <<"KeySchema">>,
            lists:map(fun key_schema_payload/1, List)
        }
    ],
    json_encode(Json).


delete_item(Config, TableName, Key, Value) ->
    delete_item(Config, TableName, {Key, Value}).

delete_item(Config, TableName, KV) ->
    Target = x_amz_target(delete_item),
    Payload = delete_item_payload(TableName, KV),
    case post(Config, Target, Payload) of
        {ok, _Json} ->
            ok;
        {error, Reason} ->
            ?debugVal(Reason),
            error(Reason)
    end.


delete_item_payload(TableName, KV) ->
    Json = [{<<"TableName">>, TableName},
            {<<"Key">>, typed_item(KV)}],
    json_encode(Json).


delete_table(Config, TableName) ->
    Target = x_amz_target(delete_table),
    Payload = delete_table_payload(TableName),
    case post(Config, Target, Payload) of
	{ok, _JSON} ->
	    ok;
	{error, Reason} ->
	    error(Reason)
    end.


delete_table_payload(TableName) ->
    Json = [{<<"TableName">>, TableName}],
    json_encode(Json).


-spec update_item(#ddb_config{}, binary(), [{binary(), [{binary(),binary()}]}], [{binary(), binary(), binary()}]) -> term().
update_item(Config, TableName, KTV, AttributeUpdates) ->
    Target = x_amz_target(update_item),
    Payload = update_item_payload(TableName, KTV, AttributeUpdates),
    case post(Config, Target, Payload) of
        {ok, _Json} ->
            ok;
        {error, Reason} ->
            ?debugVal(Reason),
            error(Reason)
    end.

-spec update_item(#ddb_config{}, binary(), binary(), binary(), [{binary(), binary(), binary()}]) -> term().
update_item(Config, TableName, Key, Value, AttributeUpdates) ->
    update_item(Config, TableName, [{Key, Value}], AttributeUpdates).


%% AttributeUpdates [{AttributeName, Action, Value}] 
update_item_payload(TableName, KV, AttributeUpdates) ->
    F = fun({AttributeName, Action, V}) ->
                {AttributeName, [{<<"Action">>, Action},
                                 {<<"Value">>, typed_value(V)}]}
        end,
    AttributeUpdates1 = lists:map(F, AttributeUpdates),
    Json = [{<<"TableName">>, TableName},
            {<<"Key">>, typed_item(KV)},
            {<<"AttributeUpdates">>, AttributeUpdates1}],
    json_encode(Json).


-spec scan(#ddb_config{}, binary()) -> not_found | [{binary(), binary()}].
scan(Config, TableName) ->
  {Items, undefined} = scan(Config, TableName, undefined),
  Items.

-spec scan(#ddb_config{}, binary(), integer()) -> {not_found | [{binary(), binary()}], undefined | binary()}.
scan(Config, TableName, Limit) ->
  scan(Config, TableName, Limit, undefined).

-spec scan(#ddb_config{}, binary(), integer(), binary()) -> {not_found | [{binary(), binary()}], undefined | binary()}.
scan(Config, TableName, Limit, ExclusiveStartKey) ->
  scan(Config, TableName, Limit, ExclusiveStartKey, undefined, undefined).

-spec scan(#ddb_config{}, binary(), integer(), binary(), binary(), [{binary(), binary()}]) -> {[{binary(), binary()}], undefined | binary()}.
scan(Config, TableName, Limit, ExclusiveStartKey, FilterExpression, ExpressionAttributeValues) ->
    Target = x_amz_target(scan),
    Payload = scan_payload(TableName, Limit, ExclusiveStartKey, FilterExpression, ExpressionAttributeValues),
    scan_request(Config, Target, Payload).


scan_payload(TableName, Limit, ExclusiveStartKey, FilterExpression, ExpressionAttributeValues) ->
    Json = [{<<"TableName">>, TableName},
            {<<"ReturnConsumedCapacity">>, <<"TOTAL">>}],
    JsonWithLimit = add_limit_to_scan_payload(Json, Limit),
    JsonWithExclusiveStartKey = add_exclusive_start_key_to_scan_payload(JsonWithLimit, ExclusiveStartKey),
    JsonWithFilter = add_filter_to_scan_payload(JsonWithExclusiveStartKey, FilterExpression, ExpressionAttributeValues),
    json_encode(JsonWithFilter).


add_limit_to_scan_payload(Json, undefined) ->
    Json;
add_limit_to_scan_payload(Json, Limit) ->
    [{<<"Limit">>, Limit} | Json].


add_exclusive_start_key_to_scan_payload(Json, undefined) ->
    Json;
add_exclusive_start_key_to_scan_payload(Json, ExclusiveStartKey) ->
    [{<<"ExclusiveStartKey">>, typed_item(ExclusiveStartKey)} | Json].


add_filter_to_scan_payload(Json, undefined, undefined) ->
    Json;
add_filter_to_scan_payload(Json, FilterExpression, ExpressionAttributeValues) ->
    JsonWithExpression = [{<<"FilterExpression">>, FilterExpression} | Json],
    Values = typed_item(ExpressionAttributeValues),
    [{<<"ExpressionAttributeValues">>, Values} | JsonWithExpression].


scan_request(Config, Target, Payload) ->
    case post(Config, Target, Payload) of
        {ok, Json} ->
            Items = proplists:get_value(<<"Items">>, Json),
            LastEvaluatedKey = proplists:get_value(<<"LastEvaluatedKey">>, Json, undefined),
            {cast_items(Items), cast_last_evaluated_key(LastEvaluatedKey)};
        {error, Reason} ->
            ?debugVal(Reason),
            error(Reason)
    end.
 

cast_last_evaluated_key(undefined) ->
    undefined;
cast_last_evaluated_key(LastEvaluatedKey) ->
    cast_item(LastEvaluatedKey).


cast_items(Items) ->
    lists:map(fun cast_item/1, Items).


cast_item(Item) ->
    lists:map(fun cast_attribute/1, Item).


cast_attribute({AttributeName, [{<<"N">>, V}]}) ->
    {AttributeName, binary_to_integer(V)};
cast_attribute({AttributeName, [{_T, V}]}) ->
    {AttributeName, V}.


-spec x_amz_target(atom()) -> binary().
x_amz_target(batch_get_item) ->
    error(not_implemented);
x_amz_target(batch_write_item) ->
    error(not_implemented);
x_amz_target(create_table) ->
    <<"DynamoDB_20120810.CreateTable">>;
x_amz_target(delete_item) ->
    <<"DynamoDB_20120810.DeleteItem">>;
x_amz_target(delete_table) ->
    <<"DynamoDB_20120810.DeleteTable">>;
x_amz_target(describe_table) ->
    error(not_implemented);
x_amz_target(get_item) ->
    <<"DynamoDB_20120810.GetItem">>;
x_amz_target(list_tables) ->
    <<"DynamoDB_20120810.ListTables">>;
x_amz_target(put_item) ->
    <<"DynamoDB_20120810.PutItem">>;
x_amz_target(query) ->
    error(not_implemented);
x_amz_target(scan) ->
    <<"DynamoDB_20120810.Scan">>;
x_amz_target(update_item) ->
    <<"DynamoDB_20120810.UpdateItem">>;
x_amz_target(update_table) ->
    error(not_implemented);
x_amz_target(_OperationName) ->
    error({not_implemented, _OperationName}).


url(true, Endpoint) ->
    <<"https://", Endpoint/binary>>;
url(false, Endpoint) ->
    <<"http://", Endpoint/binary>>.


post(#ddb_config{
        credentials = Credentials,
        service = Service,
        region = Region,
        endpoint = Endpoint,
        is_secure = IsSecure
       }, Target, Payload) ->
    Headers0 = [{<<"x-amz-target">>, Target}, 
                {<<"host">>, Endpoint}],
    DateTime = aws:iso_8601_basic_format(os:timestamp()),
    Headers = aws:signature_version_4_signing(DateTime, Credentials, Headers0,
                                              Payload, Service, Region),
    Headers1 = [{<<"accept-encoding">>, <<"identity">>},
                {<<"content-type">>, <<"application/x-amz-json-1.0">>}|Headers],

    Url = url(IsSecure, Endpoint),

    case hackney:post(Url, Headers1, Payload, [{pool, default}]) of
        {ok, 200, _RespHeaders, ClientRef} ->
            {ok, Body} = hackney:body(ClientRef),
            {ok, json_decode(Body)};
        {ok, _StatusCode, _RespHeaders, ClientRef} ->
            {ok, Body} = hackney:body(ClientRef),
            Json = json_decode(Body),
            Type = proplists:get_value(<<"__type">>, Json),
            Message = proplists:get_value(<<"Message">>, Json),
            {error, {Type, Message}}
    end.


