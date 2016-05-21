-module(imds).
-export([region/0, iam/1]).

text(Path) ->
  {ok,200,_,ClientRef}=hackney:get(<<"http://169.254.169.254/latest/", Path/binary>>, []),
  {ok, Body} = hackney:body(ClientRef),
  Body.
json(Path) -> jsone:decode(text(Path), [{object_format,proplist}]).

region() -> proplists:get_value(<<"region">>, json(<<"dynamic/instance-identity/document">>)).

iam(Name) -> json(<<"meta-data/iam/security-credentials/", Name/binary>>) ++ [{<<"Name">>, Name}].

