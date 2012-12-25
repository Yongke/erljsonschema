%% @author Yongke Wang <wangyongke@gmail.com>
%% @doc An simple json schema validator in Erlang, follow JSON Schema(draft v3)
%% http://tools.ietf.org/html/draft-zyp-json-schema-03

-module(erljsonschema).
-export([validate/2]).

-record(state, 
        { 
          title,
          description,
          default,
          %% type
          type = <<"any">>,        % simple type or list of simple type
          disallow,
          %% instance is object
          properties = [],
          patternProperties = [],
          additionalProperties,    % false or #state{}
          required = false,
          dependencies = [],
          %% instance is number
          minimum,
          maximum,
          exclusiveMinimum=false,
          exclusiveMaximum=false,
          divisibleBy,
          %% instance is array
          items,                   % #state{} or list of #state{}
          additionalItems,         % false or #state{} or {[<<"$ref">>, Ref]}
          minItems,
          maxItems,
          uniqueItems=false,
          %% instance is string
          pattern,
          minLength,
          maxLength,
          enum = [],
          format,
          
          %% $ref, $schema
          '$ref'
        }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% @spec validate(iolist(), iolist()) -> valid
%% @doc Validate if the JSON follows the schema or not. 
validate(Schema, Json) ->
    RootState = load_schema(Schema),
    put(<<"#">>, RootState),
    Value1 = decode(Json),
    validate_value(RootState, Value1).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
validate_value(State, Value) ->
    check_type(State, Value),
    check_enum(State, Value),
    check_format(State, Value).

check_type(#state{type= <<"string">>}=State, Value) when is_binary(Value) ->
    check_string(State, Value);
check_type(#state{type= <<"integer">>}=State, Value) 
  when is_integer(Value) ->
    check_num_min(State, Value),
    check_num_max(State, Value),
    check_num_div(State, Value);
check_type(#state{type= <<"number">>}=State, Value) 
  when is_number(Value) ->
    check_num_min(State, Value),
    check_num_max(State, Value),
    check_num_div(State, Value);
check_type(#state{type= <<"boolean">>}, Value) when is_boolean(Value) ->
    valid;
check_type(#state{type= <<"object">>}=State, Value) 
  when is_tuple(Value) ->
    L1 = check_props(normal, State#state.properties, Value),
    L2 = check_props(pattern, State#state.patternProperties, Value),
    check_props_additional(State#state.additionalProperties, 
                           L1 ++ L2, Value),
    check_props_deps(State#state.dependencies, Value);
check_type(#state{type= <<"array">>}=State, Value) 
  when is_list(Value) ->
    check_min_max(State#state.minItems, State#state.maxItems, length(Value),
                   {not_enough_elements,too_many_elements}),
    check_uniq_items(State#state.uniqueItems, Value),
    check_items(State#state.items, Value, 
                State#state.additionalItems);
check_type(#state{type= <<"null">>}, Value) when Value=:=null ->
    valid;
check_type(#state{type= <<"any">>}=State, Value) ->
    check_type(
      State#state{type = 
                      [<<"string">>, <<"number">>, 
                       <<"integer">>, <<"boolean">>,
                       <<"object">>, <<"array">>,
                       <<"null">>]}, Value);
check_type(#state{type = {[{<<"$ref">>,URI}]}}, Value)  ->
    S = schema_of_uri(URI),
    validate_value(S, Value);
check_type(#state{type = {DecodedS}}, Value)  ->
    S = transfer_fields(DecodedS, #state{}),
    validate_value(S, Value);
check_type(#state{type = Types, disallow = Disallow}=State, Value) 
  when is_list(Types) ->
    Guess = guess_type(Value),
    check_disallow(Disallow, Guess, State, Value),
    check_list_type(Types, Guess, State, Value);
check_type(#state{type= Type}, Value) ->
    invalid(invalid_json, {type_not_conform, {Type, Value}}).

check_list_type([], Guess, #state{type=Types}, Value) ->
    invalid(invalid_json, {type_not_conform, {Types, Guess, Value}});
check_list_type([ Type | _], Type, State, Value) ->
    check_type(State#state{type=Type}, Value);
check_list_type([ Type | Tail], Guess, State, Value) when is_tuple(Type)->
    try check_type(State#state{type=Type}, Value)
    catch _:_ ->
            check_list_type(Tail, Guess, State, Value)
    end;
check_list_type([ _ | Tail], Guess, State, Value) ->
    check_list_type(Tail, Guess, State, Value).

schema_of_uri(URI) ->
    case get(URI) of
        undefined -> invalid(invalid_json, {schema_not_found_for_uri, URI});
        S -> S
    end.

check_disallow(undefined, _, _, _) ->
    valid;
check_disallow(Disallow, Guess, State, Value) ->
    Result = try check_list_type(Disallow, Guess, State, Value)
             catch _:_ -> invalid end,
    case Result of
        valid ->  invalid(invalid_json, {type_not_allowed, {Disallow, Value}});
        _ -> valid
    end.

guess_type(V) when is_binary(V) -> 
    <<"string">>;
guess_type(V) when is_number(V) ->
    <<"number">>;
guess_type(V) when is_integer(V)-> 
    <<"integer">>;
guess_type(V) when is_boolean(V) ->
    <<"boolean">>;
guess_type(V) when is_tuple(V) ->
    <<"object">>;
guess_type(V) when is_list(V) ->
    <<"array">>;
guess_type(V) when V =:= null ->
    <<"null">>.

check_string(#state{minLength=Min, maxLength=Max, pattern=Pa}, 
             Value) ->
    Value1 = binary_to_list(Value),
    L = length(Value1),
    check_min_max(Min, Max, L, {not_enough_long, too_long}),
    case Pa of 
        undefined -> valid;
        Pa1 ->
            Pa2 = binary_to_list(Pa1),
            case re:run( Value1, Pa2) of
                {match, _} -> valid;
                nomatch -> 
                    invalid(invalid_json, {string_not_match_pattern, 
                                           {Pa, Value}})
            end
    end.

check_props(_, [], _) ->
    [];
check_props(T, PropList, {Value}) ->
    check_props1(T, PropList, Value, []).

check_props1(normal, [{Name, #state{}=State} | Rest],  VL, Acc) ->
    CheckedValues=check_props_normal(Name, State, VL),
    check_props1(normal, Rest, VL, [CheckedValues|Acc]);
check_props1(pattern, [{Re, #state{}=State} | Rest],  VL, Acc) ->
    CheckedValues=check_props_pattern(Re, State, VL, []),
    check_props1(pattern, Rest, VL, [CheckedValues|Acc]);
check_props1(_, [], _, Acc) ->
    lists:flatten(Acc).

check_props_normal(Name, #state{required=true}, []) ->
    invalid(invalid_json, {required_property_undefined, Name});
check_props_normal(_, #state{}, []) ->
    [];
check_props_normal(Name, #state{}=State, [{Name, Value} | _]) ->
    validate_value(State, Value),
    [{Name, Value}];
check_props_normal(Name, #state{}=State, [ _ | Rest] ) ->
    check_props_normal(Name, State, Rest).

check_props_pattern(_, #state{}, [], Acc) ->
    Acc;
check_props_pattern(Regex, #state{}=State, 
                    [{Name, Value} | Rest], Acc) ->
    case re:run(Name, Regex) of 
        {match, _} ->
            validate_value(State, Value),
            check_props_pattern(Regex, State, Rest, [{Name,Value}|Acc]);
        nomatch ->
            check_props_pattern(Regex, State, Rest, Acc)
    end.

check_props_additional(undefined, _, _) ->
    valid;
check_props_additional(false, Checked, {VL}) ->
    NotChecked = VL -- Checked,
    case NotChecked of 
        [] -> valid;
        _ -> invalid(invalid_json, 
                     {additionalProperties_not_allowed, NotChecked})
    end;
check_props_additional({[{<<"$ref">>,Ref}]}, Checked, {VL}) ->
    NotChecked = VL -- Checked,
    check_props_additional1(schema_of_uri(Ref), NotChecked);
check_props_additional(#state{}=State, Checked, {VL}) ->
    NotChecked = VL -- Checked,
    check_props_additional1(State, NotChecked).

check_props_additional1(_, []) ->
    valid;
check_props_additional1(#state{}=State, [ {_, Value} | T ]) ->
    validate_value(State, Value),
    check_props_additional1(State, T).

check_props_deps(undefined, _) ->
    valid;
check_props_deps([], _) ->
    valid;
check_props_deps([{Name, Dep}|T], {VL}=Value) ->
    check_props_deps1(Name, Dep, VL, Value),
    check_props_deps(T, Value).

check_props_deps1(_, _, [], _) ->
    valid;
check_props_deps1(Name, #state{}=S, [{Name, _}|_], Value)  ->
    validate_value(S, Value);
check_props_deps1(Name, Dep, [{Name, _}|_], Value)  ->
    B = has_prop(Dep, Value),
    if B -> valid;
       true ->
            invalid(invalid_json, {missing_dependency, Dep})
    end;
check_props_deps1(Name, Dep, [_|T], Value) ->
    check_props_deps1(Name, Dep, T, Value).

has_prop(Name, {L}) when is_binary(Name) ->
    lists:keymember(Name, 1, L);
has_prop(Names, {L}) when is_list(Names)->
    Props = [ K ||{K, _} <- L],
    I = Names -- Props,
    case I of 
        [] -> true;
        _ -> false
    end.

check_num_min(#state{minimum=undefined}, _) ->
    valid;
check_num_min(#state{minimum=Min, exclusiveMinimum=false}, Num) 
  when Num >= Min ->
    valid;
check_num_min(#state{minimum=Min, exclusiveMinimum=true}, Num) 
  when Num > Min ->
    valid;
check_num_min(#state{}, Num) ->
    invalid(invalid_json, {number_smaller_than_min, Num}).

check_num_max(#state{maximum=undefined}, _) ->
    valid;
check_num_max(#state{maximum=Max, exclusiveMaximum=false}, Num) 
  when Num =< Max ->
    valid;
check_num_max(#state{maximum=Max, exclusiveMaximum=true}, Num) 
  when Num < Max ->
    valid;
check_num_max(#state{}, Num) ->
    invalid(invalid_json, {number_greater_than_max, Num}).

check_min_max(undefined, undefined, _, _) ->
    valid;
check_min_max(undefined, Max, L, {_, MaxEx}) ->
    if L =< Max -> valid;
       true -> invalid(invalid_json, {MaxEx, Max})
    end;
check_min_max(Min, undefined, L, {MinEx, _}) ->
    if L >= Min -> valid;
       true -> invalid(invalid_json, {MinEx, Min})
    end;
check_min_max(Min, Max, L, Ex) ->
    check_min_max(Min, undefined, L, Ex),
    check_min_max(undefined, Max, L, Ex).

check_num_div(#state{divisibleBy=undefined}, _) ->
    valid;
check_num_div(#state{divisibleBy=Div}, Num) ->
    R = Num / Div,
    R1 = round(R) - R,
    if R1 == 0 -> valid;
       true -> invalid(invalid_json, {not_divisible, {Num, Div}})
    end.

check_items(undefined, _, _) ->
    %% if items not defined, means allows any value for items 
    %% in the instance array
    valid;
check_items(#state{}, [], _) ->
    valid;
check_items(#state{}=ItemSchema, [ H | T ], AdditionalItems) ->
    validate_value(ItemSchema, H),
    check_items(ItemSchema, T, AdditionalItems);
check_items({[{<<"$ref">>,Ref}]}=ItemSchema, [ H | T ], AdditionalItems) ->
    validate_value(schema_of_uri(Ref), H),
    check_items(ItemSchema, T, AdditionalItems);

check_items([ #state{}=ItemSchema | TS ], [ H | T], AdditionalItems) ->
    validate_value(ItemSchema, H),
    check_items(TS, T, AdditionalItems);
check_items([ {[{<<"$ref">>,Ref}]} | TS ], [ H | T], AdditionalItems) ->
    validate_value(schema_of_uri(Ref), H),
    check_items(TS, T, AdditionalItems);
check_items([], [], _) ->
    valid;
check_items(L, [], _) ->
    invalid(invalid_json, {array_items_missing, L});
check_items([], L, false) ->
    invalid(invalid_json, {additional_items_not_allowed, L});
check_items([], [H|T], #state{}=ItemSchema) ->
    io:fwrite("erljsonschema:check_items/3:ItemSchema=~p~n",[ItemSchema]),
    validate_value(ItemSchema, H),
    check_items([], T, ItemSchema);
check_items([], [H|T], {[{<<"$ref">>,Ref}]}=ItemSchema) ->
    io:fwrite("erljsonschema:check_items/3:ItemSchema=~p~n",[ItemSchema]),
    validate_value(schema_of_uri(Ref), H),
    check_items([], T, ItemSchema).

check_uniq_items(true, L) ->
    S = length(L),
    S1 = length(lists:usort(L)),
    if S =:= S1 -> valid;
       true -> 
            invalid(invalid_json, {items_not_unique, L})
    end;
check_uniq_items(_, _) ->
    valid.

check_enum(#state{enum=[]}, _) ->
    valid;
check_enum(#state{enum=E}, V) ->
    case lists:member(V, E) of
        true -> valid;
        false -> invalid(invalid_json, {instance_not_in_enum, {E,V}})
    end.

check_format(undefined, _) ->
    valid;
check_format(#state{format=undefined}, _) ->
    valid;
check_format(#state{format=Format}, Value) when is_binary(Value)->
    check_format(Format, binary_to_list(Value));
check_format(#state{format=Format}, Value) ->
    check_format(Format, Value);
check_format(<<"date-time">>=F, DateTime) ->
    Re = "^([0-9]{4})-(1[0-2]|0[1-9])-(3[0-1]|0[1-9]|[1-2][0-9])"
        "T(2[0-3]|[0-1][0-9]):([0-5][0-9]):([0-5][0-9])Z\$",
    check_format(F, DateTime, Re);
check_format(<<"date">>=F, Date) ->
    Re = "^([0-9]{4})-(1[0-2]|0[1-9])-(3[0-1]|0[1-9]|[1-2][0-9])\$",
    check_format(F, Date, Re);
check_format(<<"time">>=F, Time) ->
    Re = "(2[0-3]|[0-1][0-9]):([0-5][0-9]):([0-5][0-9])\$",
    check_format(F, Time, Re);
check_format(<<"utc-millisec">>, Utcmsec) when is_number(Utcmsec)->
    valid;
check_format(<<"utc-millisec">>=F, _) ->
    invalid(invalid_json,{invalid_format, F});
check_format(<<"regex">>=F, Re) ->
    case re:compile(Re) of 
        {ok, _} ->
            valid;
        _ -> invalid(invalid_json,{invalid_format, F})
    end;        
check_format(<<"color">>=F, Color) ->
    Re = "^(aqua|black|blue|fuchsia|gray|green|lime|maroon"
        "|navy|olive|orange|purple|red|silver|teal|white|yellow"
        "|#([a-fA-F0-9]{6}|[a-fA-F0-9]{3})"
        "|rgb *\\( *[0-9]+, *[0-9]+, *[0-9]+ *\\)"
        "|rgb *\\( *[0-9]+%, *[0-9]+%, *[0-9]+% *\\))\$",
    check_format(F, Color, Re);
check_format(<<"style">>, _) ->
    valid; %not check
check_format(<<"phone">>, _) ->
    valid; %not check
check_format(<<"uri">>, _) ->
    valid; %not check
check_format(<<"email">>, _) ->
    valid; %not check
check_format(<<"ip-address">>, _) ->
    valid; %not check
check_format(<<"ipv6">>, _) ->
    valid; %not check
check_format(<<"host-name">>, _) ->
    valid; %not check
check_format(F, V) ->
    invalid(invalid_json,{invalid_format, {F,V}}).

check_format(Format, Subject, Regex) ->
    case re:run(Subject, Regex) of
        {match, _} ->
            valid;
        nomatch ->
            invalid(invalid_json,{invalid_format, Format})
    end.

%% Load schema to state
load_schema(Schema) ->
    {Schema1} = decode(Schema),
    transfer_fields(Schema1, #state{}).

transfer_fields([], S) ->
    S;
transfer_fields([{<<"type">>, Type} | Rest], S) ->
    transfer_fields(Rest, S#state{type=Type});
transfer_fields([{<<"disallow">>, Disallow} | Rest], S) ->
    transfer_fields(Rest, S#state{disallow=Disallow});
transfer_fields([{<<"default">>, Default} | Rest], S) ->
    transfer_fields(Rest, S#state{default=Default});
transfer_fields([{<<"required">>, Required} | Rest], S) ->
    Required1 = check_field(Required, fun is_boolean/1,
                            {invalid_schema, {required, not_boolean, Required}}),
    transfer_fields(Rest, S#state{required=Required1});
transfer_fields([{<<"properties">>, {Props}} | Rest], S) ->
    Props1 = transfer_props(Props, []),
    transfer_fields(Rest, S#state{properties=Props1});
transfer_fields([{<<"properties">>, Props} | _], _) ->
    invalid(invalid_schema, {properties, not_object, Props});
transfer_fields([{<<"patternProperties">>, {Pattern}} | Rest], S) ->
    Props1 = transfer_props(Pattern, []),
    transfer_fields(Rest, S#state{patternProperties=Props1});
transfer_fields([{<<"patternProperties">>, Pattern} | _], _) ->
    invalid(invalid_schema, {patternProperties, not_object, Pattern});
transfer_fields([{<<"additionalProperties">>, Additional} | Rest], S) ->
    Additional1 = is_additional(Additional),
    transfer_fields(Rest, S#state{additionalProperties=Additional1});
transfer_fields([{<<"dependencies">>, {Deps}} | Rest], S) ->
    Deps1 = transfer_deps(Deps, []),
    transfer_fields(Rest, S#state{dependencies=Deps1});
transfer_fields([{<<"dependencies">>, Deps} | _], _) ->
    invalid(invalid_schema, {dependencies, not_object, Deps});
transfer_fields([{<<"minimum">>, Min} | Rest], S)->
    Min1 = check_field(Min, fun is_number/1, 
                       {invalid_schema, {mininum, not_number, Min}}),
    transfer_fields(Rest, S#state{minimum=Min1});
transfer_fields([{<<"maximum">>, Max} | Rest], S) ->
    Max1 = check_field(Max, fun is_number/1, 
                       {invalid_schema, {mininum, not_number, Max}}),
    transfer_fields(Rest, S#state{maximum=Max1});
transfer_fields([{<<"exclusiveMinimum">>, B} | Rest], S) ->
    B1 = check_field(B, fun is_boolean/1, 
                     {invalid_schema, {exclusiveMinimum, not_boolean, B}}),
    transfer_fields(Rest, S#state{exclusiveMinimum=B1});
transfer_fields([{<<"exclusiveMaximum">>, B} | Rest], S) ->
    B1 = check_field(B, fun is_boolean/1, 
                     {invalid_schema, {exclusiveMaximum, not_boolean, B}}),
    transfer_fields(Rest, S#state{exclusiveMaximum=B1});
transfer_fields([{<<"divisibleBy">>, Div} | Rest], S) ->
    Div1 = check_field(Div, fun is_number/1,
                       {invalid_schema, {divisibleBy, not_number, Div}}),
    if Div1 =:= 0 -> 
            invalid(invalid_schema, {divisibleBy, is_zero, Div});
       true ->
            transfer_fields(Rest, S#state{divisibleBy=Div1})
    end;
transfer_fields([{<<"items">>, {Obj}} | Rest], S) ->
    transfer_fields(Rest, S#state{
                            items = transfer_fields(Obj, #state{})});
transfer_fields([{<<"items">>, URI} | Rest], S) when is_binary(URI)->
    transfer_fields(Rest, S#state{items = URI});
transfer_fields([{<<"items">>, Items} | Rest], S) when is_list(Items)->
    Items1 = check_field(Items, fun is_items_list/1,
                         {invalid_schema, {items, tuple_typing_not_object, Items}}),
    transfer_fields(Rest,S#state{
                           items = [transfer_fields(E, #state{}) 
                                    || {E} <- Items1]});
transfer_fields([{<<"items">>, Items} | _], _) ->
    invalid(invalid_schema, {items, not_object_nor_list, Items});
transfer_fields([{<<"minItems">>, Min} | Rest], S) ->
    Min1 = check_field(Min, fun is_integer/1,
                       {invalid_schema, {minItems, not_integer, Min}}),
    transfer_fields(Rest, S#state{minItems=Min1});
transfer_fields([{<<"maxItems">>, Max} | Rest], S) ->
    Max1 = check_field(Max, fun is_integer/1,
                       {invalid_schema, {maxItems, not_integer, Max}}),
    transfer_fields(Rest, S#state{maxItems=Max1});
transfer_fields([{<<"additionalItems">>, AdditionalItems} | Rest], S) ->
    Additional1 = is_additional(AdditionalItems),
    transfer_fields(Rest, S#state{additionalItems=Additional1});    
transfer_fields([{<<"uniqueItems">>, Unique} | Rest], S) ->
    Unique1 = check_field(Unique, fun is_boolean/1,
                          {invalid_schema, {uniqueItems, not_boolean, Unique}}),
    transfer_fields(Rest, S#state{uniqueItems=Unique1});
transfer_fields([{<<"pattern">>, P} | Rest], S) ->
    P1 = check_field(P, fun is_binary/1,
                     {invalid_schema, {pattern, not_string, P}}),
    transfer_fields(Rest, S#state{pattern=P1});
transfer_fields([{<<"minLength">>, L} | Rest], S) ->
    L1 = check_field(L, fun is_integer/1,
                     {invalid_schema, {minLength, not_integer, L}}),
    transfer_fields(Rest, S#state{minLength=L1});
transfer_fields([{<<"maxLength">>, L} | Rest], S) ->
    L1 = check_field(L, fun is_integer/1,
                     {invalid_schema, {maxLength, not_integer, L}}),
    transfer_fields(Rest, S#state{maxLength=L1});
transfer_fields([{<<"enum">>, E} | Rest], S) ->
    E1 = check_field(E, fun is_list/1,
                     {invalid_schema, {enum, not_list, E}}),
    L = length(lists:usort(E1)),
    case length(E1) of
        0 ->
            invalid(invalid_schema, {enum, empty_list, E1});
        L ->
            transfer_fields(Rest, S#state{enum=E1});
        _ ->
            invalid(invalid_schema, {enum, elem_in_list_not_unique, E1})
    end;
transfer_fields([{<<"format">>, F} | Rest], S) ->
    F1 = check_field(F, fun is_binary/1,
                     {invalid_schema, {format, not_string, F}}),
    transfer_fields(Rest, S#state{format=F1});
transfer_fields([{<<"$ref">>, Ref} | Rest], S) ->
    Ref1 = check_field(Ref, fun is_binary/1,
                     {invalid_schema, {'$ref', not_string, Ref}}),
    transfer_fields(Rest, S#state{format=Ref1});
transfer_fields([_ | Rest], S) ->
    transfer_fields(Rest, S).

transfer_props([], Acc) ->
    lists:reverse(Acc);
transfer_props([{Name, {PropSchema}} | Rest], Acc) ->
    transfer_props(
      Rest, [{Name, transfer_fields(PropSchema, #state{})} | Acc]);
transfer_props([{Name, PropSchema} | _], _) ->
    invalid(invalid_schema, {Name, not_object, PropSchema}).

transfer_deps([], Acc) ->
    lists:reverse(Acc);
transfer_deps([{Name, {DepSchema}} | Rest], Acc) ->
    transfer_deps(
      Rest, [ {Name, transfer_fields(DepSchema, #state{})} | Acc]);
transfer_deps([Deps | Rest], Acc) ->
    transfer_deps(Rest, [Deps | Acc]).

is_items_list([]) -> 
    true;
is_items_list([{_}|L]) -> 
    is_items_list(L);
is_items_list([_|_]) -> 
    false.

is_additional(false) ->
    false;
is_additional({[{<<"$ref">>,<<"#">>}]}=URI) ->
    URI;
is_additional({Obj}) ->
    transfer_fields(Obj, #state{});
is_additional(Ap) ->
    invalid(invalid_schema, {additional_properties, 
                             not_false_nor_schema, Ap}).

check_field(Field, Fun, {Ex, Reason}) ->
    case Fun(Field) of 
        true -> Field;
        _ -> invalid(Ex, Reason)
    end.

decode(IoList) ->
    try
        (mochijson2:decoder([{object_hook, fun({struct, L}) -> {L} end}]))(IoList)
    catch
        _:Error ->
            invalid(invalid_json, {Error, IoList})
    end.

invalid(Ex, Reason) ->
    throw({Ex, Reason}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

validate_ex(Schema, Value) ->
    try validate(Schema, Value) 
    catch throw:{_, {R,_}} -> 
            R;
          throw:{_, {_, R, _}} ->
            R
    end.

testcases() ->
    [{type_not_allowed, "{\"disallow\":[\"number\",\"string\"]}", "\"hello\""},
     {valid, "{\"type\":\"string\"}", "\"123\""},
     {valid, "{\"type\":\"number\"}", "123"},
     {valid, "{\"type\":\"number\"}", "0.001"},
     {valid, "{\"type\":\"integer\"}", "123"},
     {type_not_conform, "{\"type\":\"integer\"}", "123.0"},
     {valid, "{\"type\":\"boolean\"}", "true"},
     {valid, "{\"type\":\"boolean\"}", "false"},
     {valid, "{\"type\":\"object\"}", "{}"},
     {valid, "{\"type\":\"object\"}", "{\"k\":\"v\"}"},
     {valid, "{\"type\":\"array\"}", "[]"},
     {valid, "{\"type\":\"array\"}", "[\"a\",1]"},
     {valid, "{\"type\":\"null\"}", "null"},
     {valid, "{\"type\":\"any\"}", "\"123\""},
     {valid, "{\"type\":\"any\"}", "123"},
     {valid, "{\"type\":\"any\"}", "0.001"},
     {valid, "{\"type\":\"any\"}", "123"},
     {valid, "{\"type\":\"any\"}", "123.0"},
     {valid, "{\"type\":\"any\"}", "true"},
     {valid, "{\"type\":\"any\"}", "false"},
     {valid, "{\"type\":\"any\"}", "{}"},
     {valid, "{\"type\":\"any\"}", "{\"k\":\"v\"}"},
     {valid, "{\"type\":\"any\"}", "[]"},
     {valid, "{\"type\":\"any\"}", "[\"a\",1]"},
     {valid, "{\"type\":\"any\"}", "null"},
     {valid, "{\"type\":[\"number\", \"string\"]}", "1"},
     {valid, "{\"type\":[\"number\", \"string\"]}", "\"string\""},
     {valid, "{\"type\":[\"number\", \"string\", {\"properties\":"
      "{\"a\":{\"required\":true}}}]}", "{\"a\":{}}"},
     {type_not_conform, "{\"type\":[\"number\", {\"properties\":"
      "{\"a\":{\"required\":true}}}, \"string\"]}", "{}"},
     {type_not_conform, "{\"type\":[\"number\", \"string\"]}", "false"},
     {number_smaller_than_min, "{\"type\":[\"number\", \"string\"], "
      "\"minimum\":10.3}", "5"},
     {valid, "{\"type\":\"string\"}", "\"123\""},
     {not_string, "{\"type\":\"string\",\"pattern\":{}}", "\"123\""},
     {valid, "{\"type\":\"string\",\"pattern\":\"^abc.*g\$\"}", "\"abcdefg\""},
     {string_not_match_pattern, "{\"type\":\"string\",\"pattern\":\"^abc.*g\$\"}",
      "\"abcd3\""},
     {not_enough_long, "{\"type\":\"string\",\"maxLength\":4, \"minLength\":2}",
      "\"s\""},
     {valid, "{\"type\":\"object\",\"properties\":{}}","{\"pkey\": 1}"},
     {not_object, "{\"type\":\"object\",\"properties\":2}", "{}"},    
     {valid, "{\"type\":\"object\",\"properties\":{\"pkey\":"
      "{\"type\":\"number\"}}}", "{\"pkey\": 1}"},
     {valid, "{\"type\":\"object\",\"properties\":{\"pkey\":{}}}","{\"pkey\": 1}"},
     {not_object, "{\"type\":\"object\",\"properties\":{\"pkey\":false}}", "{}"},
     {not_object, "{\"type\":\"object\",\"properties\":{\"pkey\":1}}","{}"},
     {required_property_undefined, "{\"type\":\"object\",\"properties\":"
      "{\"pkey\":{\"type\":\"number\",\"required\":true}}}", "{}"},
     {valid, "{\"type\":\"object\",\"patternProperties\":{}}", "{}"},
     {not_object, "{\"type\":\"object\",\"patternProperties\":33}", "{}"},
     {not_object, "{\"type\":\"object\",\"patternProperties\":{\"a+\":44}}", "{}"},
     {valid, "{\"properties\":{\"p\":{}},\"patternProperties\":{\"^a\":{}}}", 
      "{\"a\":false,\"a1\":null,\"a3\":null}"},
     {valid, "{\"properties\":{\"p\":{}},\"patternProperties\":"
      "{\"^a\":{}, \"x\$\":{}}}", "{\"a\":false,\"a1\":null,\"zt\":null}"},
     {valid, "{\"type\":\"object\",\"additionalProperties\":false}", "{}"},
     {valid, "{\"type\":\"object\","
      "\"properties\":{\"p\":{}},"
      "\"additionalProperties\":{ \"$ref\": \"#\" }}", 
      "{}"},
     {required_property_undefined, "{\"type\":\"object\","
      "\"properties\":{\"p\":{\"required\":true}},"
      "\"additionalProperties\":{ \"$ref\": \"#\" }}", 
      "{\"p\":3, \"a\":{}}"},
     {not_false_nor_schema, "{\"type\":\"object\","
      "\"additionalProperties\":true}", "{}"},
     {valid, "{\"properties\":{\"p\":{}},\"patternProperties\":"
      "{\"^a\":{}},\"additionalProperties\":false}", 
      "{\"p\":false,\"a1\":null,\"a3\":null}"},
     {additionalProperties_not_allowed, "{\"properties\":{\"p\":{}},"
      "\"patternProperties\":{\"^a\":{}},\"additionalProperties\":false}", 
      "{\"p\":false,\"a1\":1,\"t\":null}"},
     {valid,"{\"dependencies\":{\"p\":{\"properties\":"
      "{\"a\":{\"required\":true}}},\"b\":\"c\"}}", 
      "{\"p\":null,\"a\":3,\"b\":1,\"c\":0.1}"},
     {valid, "{\"dependencies\":{\"p\":{\"properties\":"
      "{\"a\":{\"required\":true}}},\"b\":[\"c\", \"d\"]}}", 
      "{\"p\":null,\"a\":3,\"b\":1,\"c\":0.1,\"d\":true}"},
     {required_property_undefined,"{\"dependencies\":{\"p\":{\"properties\":"
      "{\"a\":{\"required\":true}}},\"b\":\"c\"}}", 
      "{\"p\":null,\"b\":1,\"c\":0.1}"},
     {missing_dependency, "{\"dependencies\":{\"p\":"
      "{\"properties\":{\"a\":{\"required\":true}}},\"b\":\"c\"}}", 
      "{\"p\":null,\"a\":true,\"b\":1}"},
     {valid, "{\"type\":\"number\", \"minimum\":10}", "123.0"},
     {number_smaller_than_min, "{\"type\":\"number\", \"minimum\":10.3}", "5.0"},
     {valid, "{\"type\":\"integer\", \"maximum\": 500}", "123"},
     {number_greater_than_max, "{\"type\":\"integer\", \"maximum\": 500}", "800"},
     {valid, "{\"type\":\"number\",\"divisibleBy\":-3.1}","6.2"},
     {not_divisible, "{\"type\":\"integer\",\"divisibleBy\":4}","7"},
     {valid, "{\"type\":\"array\", \"uniqueItems\":true}", 
      "[\"abc\", \"def\", 1]"},
     {items_not_unique, "{\"type\":\"array\", \"uniqueItems\":true}", 
      "[1, \"abc\", \"def\", 1]"},
     {valid, "{\"type\":\"array\", \"items\":{}}", "[\"abc\", \"def\", 1]"},
     {type_not_conform, "{\"type\":\"array\", \"items\":{\"type\":\"string\"}}", 
      "[\"abc\", \"def\", 1]"},
     {valid, "{\"type\":\"array\", \"items\":{}}", "[\"abc\", \"def\", 1]"},
     {valid, "{\"minItems\":1, \"maxItems\":3}", "[1,2,3]"},
     {type_not_conform, "{\"type\":\"object\", \"properties\":{"
      "\"a\":{ \"type\": \"array\", \"items\":[{\"type\": \"string\"}],"
      "\"additionalItems\":{ \"$ref\": \"#\" }}}}", "{\"a\":[1]}"},
     {valid, "{\"type\":\"object\", \"properties\":{"
      "\"a\":{ \"type\": \"array\", \"items\":[{\"type\": \"string\"}],"
      "\"additionalItems\":{ \"$ref\": \"#\" }}}}", "{\"a\":[\"str\"]}"},
     {valid, "{\"type\":\"object\", \"properties\":{"
      "\"a\":{ \"type\": \"array\", \"items\":[{\"type\": \"string\"}],"
      "\"additionalItems\":{ \"$ref\": \"#\" }}}}", "{\"a\":[\"str\",{},{}]}"},
     {valid,"{\"type\":\"array\",\"items\":[{},{},{}]}","[\"abc\",\"def\",1]"},
     {valid,"{\"type\":\"array\",\"items\":[{},{},{}],\"additionalItems\":false}",
      "[\"abc\", \"def\", 1]"},
     {valid, "{\"type\":\"array\", \"items\":[{},{},{}],"
      "\"additionalItems\": {\"type\":\"string\"}}", 
      "[\"abc\", \"def\", 1, \"hello\", \"you\"]"},
     {additional_items_not_allowed, "{\"type\":\"array\", "
      "\"items\":[{},{},{}],\"additionalItems\": false}", 
      "[\"abc\", \"def\", 1, false]"},
     {array_items_missing, "{\"type\":\"array\", \"items\":[{},{},{}],"
      "\"additionalItems\": false}", "[\"abc\", \"def\"]"},
     {elem_in_list_not_unique, "{\"enum\":[1,1,[1,2,3]]}", "[1,2,3]"},
     {valid, "{\"enum\":[1,{},[1,2,3]]}", "[1,2,3]"},
     {valid, "{\"enum\":[\"1\",{},[1,2,3]]}", "\"1\""},
     {instance_not_in_enum, "{\"enum\":[1,{\"has\":true},[1,2,3]]}", 
      "{\"has\":false}"},
     {valid, "{\"type\":\"string\",\"format\":\"date-time\"}", 
      "\"2012-11-28T15:05:17Z\""},
     {invalid_format, "{\"type\":\"string\",\"format\":\"date-time\"}", 
      "\"2012-11-28\""},
     {valid, "{\"type\": \"object\","
      "\"properties\":{\"a\":{"
      "\"type\":[\"string\", { \"$ref\": \"#\" }]}}}", "{\"a\":\"temp\"}"},
     {valid, "{\"type\": \"object\","
      "\"properties\":{\"a\":{"
      "\"type\":[\"string\", { \"$ref\": \"#\" }]}}}", "{\"a\":{}}"}
    ].

%% validate_test() ->
%%     [?assertEqual(Eexpect, validate_ex(Schema, Json)) 
%%      || {Eexpect, Schema, Json} <- testcases()].

validate_test() ->
    [?assertEqual({Eexpect, {Schema, Json}}, {validate_ex(Schema, Json), {Schema, Json}}) 
     || {Eexpect, Schema, Json} <- testcases()].

-endif.

