-module(core_self_validate_SUITE).
-include_lib("common_test/include/ct.hrl").

-compile(export_all).

-define(value(Key,Config), proplists:get_value(Key,Config)).

suite() -> [{timetrap, {seconds, 20}}].

groups() -> [].

all() ->
    [ {exports, Functions} | _ ] = ?MODULE:module_info(),
    [ FName || {FName, _} <- lists:filter(
                               fun ({module_info,_}) -> false;
                                   ({all,_}) -> false;
                                   ({init_per_suite,1}) -> false;
                                   ({end_per_suite,1}) -> false;
                                   ({_,1}) -> true;
                                   ({_,_}) -> false
                               end, Functions)].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_group, Config) ->
    Config.

end_per_group(_group, Config) ->
    Config.

init_per_testcase(core_self, Config) ->
    {ok,CoreSchema} = file:read_file("../../test/draft_v3/schema"),
    Json = CoreSchema,
    [{core_self, {CoreSchema, Json}}|Config].

end_per_testcase(_, Config) ->
    Config.

core_self() ->
    [{userdata,[{doc,"Testing self-validation of core schema"}]}].

core_self(Config) ->
    {Schema, Json} = ?value(core_self, Config),
    erljsonschema:validate(Schema, Json).
