-module(imds).
-export([region/0, iam/1]).

text(Path) ->
  {ok,200,_,ClientRef}=hackney:get(<<"http://169.254.169.254/latest/meta-data/", Path/binary>>, []),
  {ok, Body} = hackney:body(ClientRef),
  Body.
json(Path) -> jsone:decode(text(Path)).

region() -> text(<<"placement/availability-zone">>).
iam(Name) -> json(<<"iam/security-credentials/", Name/binary>>).
  



