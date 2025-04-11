-module(eims_format).
-compile(export_all).

-include("eims.hrl").
-include_lib("xmpp/include/xmpp.hrl").

-include("fix_fields.hrl").


-record(format, {key = [], name = [], value = []}).

%% API

-define(D, 1). %% spaces in one tab
-define(DELIMITER, $\s).
-define(TV_COL_SIZE, 17).

-define(PRIV_CMDS, <<"private:">>).
-define(PUB_CMDS, <<"public:">>).
-define(CUSTOM_CMDS, <<"custom:">>).
-define(HELP_HEAD(Cmd), <<(cmd(Cmd))/binary, " triggered by /", Cmd/binary, "\n">>).

-define(rfq_req, <<"rfq_req">>).
-define(tv, <<"tv">>).

-spec entity_type(key | value | header | command | command_doc | atom()) ->
	bold | bot_command | code | hashtag | italic | mention | monospace | pre | spoiler | strikethrough | text_link | undefined | underline.
entity_type(header)         ->  bold; %% TODO move to config
entity_type(key)            ->  code;
entity_type(value)          ->  code;
entity_type(tv_key)         ->  code;
entity_type(tv_value)       ->  code;
entity_type(command)        ->  bot_command;
entity_type(command_doc)    ->  italic;
entity_type(Type)           ->  Type.

-spec header(summary | position | user | binary()) -> binary().
header(summary)                         -> <<"Account Summary:">>;
header(position)                        -> <<"\nPosition:">>;
header(user)                            -> <<"\tUser info:">>;
header(<<"user.access_log">>)           -> <<" channel info:">>;
header(Header) when is_binary(Header)   -> Header.

header(tv, Total)                       -> "\nMy " ++ binary_to_list(Total) ++ " trade volume\n".

-spec cmd(binary()) -> binary().
cmd(?tv) -> <<"trade volumes">>;
cmd(Cmd) -> Cmd.

-spec entity(key | value | header | atom(), non_neg_integer() | binary() | string()) -> message_entity().
entity(Type, Text) when is_binary(Text); is_list(Text); is_integer(Text) ->
	entity(Type, Text, 0).

-spec entity(key | value | header | atom(), non_neg_integer() | binary() |string(), non_neg_integer() | binary() | string()) -> message_entity().
entity(Type, Text, Offset) when is_list(Offset) ->
	entity(Type, Text, length(Offset));
entity(Type, Text, Offset) when is_list(Text) ->
	entity(Type, length(Text), Offset);
entity(Type, Text, Offset) when is_binary(Offset) ->
	entity(Type, Text, byte_size(Offset));
entity(Type, Text, Offset) when is_binary(Text) ->
	entity(Type, byte_size(Text), Offset);
entity(Type, Length, Offset) when is_integer(Length), is_integer(Offset) ->
	#message_entity{offset = Offset, length = Length, type = entity_type(Type)}.

-spec format_list(summary | position | user | binary(), map()) -> list(#format{}).
format_list(summary, _Map) -> %% ordered params for output
	Summary = [{<<"system_name">>, <<"User nickname">>},
		{<<"username">>, <<"Account name">>},
		{<<"type">>, <<"Type">>},
		{<<"email">>, <<"Email">>},
		{<<"tfa_enabled">>, <<"Two Factor Authentication">>},
		{<<"deposit_address">>, <<"Deposit Address">>},
		{<<"referrer_id">>, <<"Referrer ID">>},
		{<<"portfolio_margining_enabled">>, <<"Portfolio Margining">>},
		{<<"interuser_transfers_enabled">>, <<"Interuser Transfers">>},
		{<<"available_funds">>, <<"Available Funds">>},
		{<<"available_withdrawal_funds">>, <<"Available Withdrawal Funds">>},
		{<<"limits">>, <<"Limits">>},
		{<<"non_matching_engine">>, <<"non matching engine">>},
		{<<"matching_engine">>, <<"matching engine">>},
		{<<"rate">>, <<"rate">>},
		{<<"burst">>, <<"burst">>},
		{<<"currency">>, <<"Currency">>},
		{<<"total_pl">>, <<"Profit&Loss">>},
		{<<"equity">>, <<"Equity">>},
		{<<"balance">>, <<"Balance">>},
		{<<"margin_balance">>, <<"Margin Balance">>},
		{<<"initial_margin">>, <<"Initial Margin">>},
		{<<"projected_initial_margin">>, <<"Initial Margin (projected)">>},
		{<<"maintenance_margin">>, <<"Maintenance Margin">>},
		{<<"projected_maintenance_margin">>, <<"Maintenance Margin (projected)">>},
		{<<"delta_total">>, <<"Delta Total">>},
		{<<"projected_delta_total">>, <<"Delta Total (projected)">>},
		{<<"session_upl">>, <<"Session unrealized profit&loss">>},
		{<<"session_rpl">>, <<"Session realized profit&loss">>},
		{<<"futures_pl">>, <<"Futures profit&loss">>},
		{<<"futures_session_rpl">>, <<"Futures Session realized profit&loss">>},
		{<<"futures_session_upl">>, <<"Futures Session unrealized profit&loss">>},
		{<<"options_pl">>, <<"Options profit&loss">>},
		{<<"options_value">>, <<"Options value">>},
		{<<"options_session_upl">>, <<"Options Session unrealized profit&loss">>},
		{<<"options_session_rpl">>, <<"Options Session realized profit&loss">>},
		{<<"options_gamma">>, <<"Options Gamma">>},
		{<<"options_theta">>, <<"Options Theta">>},
		{<<"options_delta">>, <<"Options Delta">>},
		{<<"options_vega">>, <<"Options Vega">>}],
	[#format{key = K, name = PK} || {K, PK} <- Summary];
format_list(position, _Map) ->
	Position = [{<<"instrument_name">>, <<"Instrument name">>},
		{<<"direction">>, <<"Direction">>},
		{<<"size">>, <<"Size">>},
		{<<"size_currency">>, <<"Size Currency">>},
		{<<"average_price">>, <<"Avg. price">>},
		{<<"delta">>, <<"Delta">>},
		{<<"gamma">>, <<"Gamma">>},
		{<<"theta">>, <<"Theta">>},
		{<<"vega">>, <<"Vega">>}],
	[#format{key = K, name = PK} || {K, PK} <- Position];
format_list(user, _Map) ->
	User = [{<<"jid">>, <<"Jid">>},
		{<<"nick">>, <<"Nick">>},
		{<<"system_name">>, <<"System Name">>},
		{<<"main_system_name">>, <<"MainSystemName">>},
		{<<"email">>, <<"Email">>},
		{<<"main_email">>, <<"MainEmail">>},
		{<<"id">>, <<"Id">>},
		{<<"main_account_id">>, <<"MainUId">>},
		{<<"roles">>, <<"Roles">>},
		{<<"ip">>, <<"IP">>}],
	[#format{key = K, name = PK} || {K, PK} <- User];
format_list(<<"user.access_log">>, _Map) ->
	AccessLog = [{<<"timestamp">>, <<"Access Time">>},
		{<<"log">>, <<"Log">>},
		{<<"ip">>, <<"IP">>},
		{<<"country">>, <<"Country">>},
		{<<"city">>, <<"City">>}],
	[#format{key = K, name = PK} || {K, PK} <- AccessLog];
format_list(Name, Map) when is_binary(Name) ->
	[begin
		 K2 = case is_atom(K) of true -> atom_to_binary(K); _ -> K end,
		 #format{key = K2, name = K2}
	end || {K, _} <- maps:to_list(Map)];
format_list(_, _) -> [].

-spec fill_format_list(list(#format{}) | atom() | binary(), map() | binary()) -> list(#format{}) | binary().
fill_format_list(_, Map) when Map == #{} ->
	<<>>;
fill_format_list([#format{} | _] = FormatList, #{} = Map) ->
	lists:foldl(
		fun(#format{key = K, name = PrKey} = F, {ResList, MaxKeySize}) when is_map_key(K, Map) ->
			Value = fill_format_list(FormatList, maps:get(K, Map)),
			PrKey2 = case PrKey of [] -> K; _ -> PrKey end,
			KeySize = byte_size(PrKey2),
			{ResList ++ [F#format{value = Value, name = PrKey2}],
				case MaxKeySize < KeySize of true -> KeySize; _ -> MaxKeySize end};
			(_, Acc) -> Acc
		end, {[], 0}, FormatList);
fill_format_list([], #{}) ->
	<<"[]">>;
fill_format_list(RequestName, #{} = Map) ->
	fill_format_list(format_list(RequestName, Map), Map);
%%fill_format_list(RequestName, [_ | _] = L) -> %% TODO implement list of maps
%%	lists:foldl( %% not works
%%		fun(Map = #{}, Acc) ->
%%				Acc ++ fill_format_list(format_list(RequestName, Map), Map);
%%			(V, Acc) ->
%%				Acc ++ [V]
%%		end, [], L);
fill_format_list(_RequestName, Val) ->
	Val.

do_text({[], 0}) -> {[], []};
do_text({[#format{} | _] = L, N}) ->
	do_text({L, N}, {0, {[], []}}).
do_text({[], _}, {_, {_S, _Entities} = Acc}) -> Acc;
do_text({[#format{} = F | T], N}, {I, Acc}) ->
	do_text({T, N}, {I, do_text({F, N}, {I, Acc})});
do_text({#format{value = []}, _N}, {_I, Acc}) -> Acc;
do_text({#format{name = K, value = {[#format{} | _], _N2} = V}, _N}, {I, {S, Es} = _Acc}) ->
	S2 = S ++ lists:duplicate(I, ?DELIMITER),
	Es2 = Es ++ [entity(key, byte_size(K), length(S2))],
	do_text(V, {I + 1, {S2 ++ binary_to_list(K) ++ "\n", Es2}});
do_text({#format{name = K, value = V}, N}, {I, {S, Es}}) ->
	KeySize = byte_size(K),
	NOffset = (N - KeySize) div ?D + 1,
	Offset = length(S) + I,
	Es2 = Es ++ [entity(key, KeySize + NOffset, Offset), entity(value, length(Obj = format(V)), Offset + KeySize + NOffset)],
	{S ++ lists:duplicate(I, ?DELIMITER) ++ binary_to_list(K) ++ lists:duplicate(NOffset, ?DELIMITER) ++ Obj ++ "\n", Es2}.

format(L) when is_list(L) ->
	{_, R} =
		lists:foldl(
			fun(V, {N, Acc}) ->
				{N - 1, Acc ++ format(V) ++ case N of 1 -> ""; _ -> ", " end}
			end, {length(L), ""}, L),
	"[" ++ R ++ "]";
format(V) when is_float(V) ->
	S = float_to_list(V, [{decimals, 7}]),
	[I, D] = string:split(S, "."),
	string:strip(string:join([I, string:strip(D, right, $0)], "."), right, $.);
format(V) when is_binary(V); is_atom(V) ->
	lists:flatten(io_lib:format("~s", [V]));
format(V) ->
	lists:flatten(io_lib:format("~p", [V])).

map_to_format(Map, _FormatList) when Map == #{} ->
	<<>>;
map_to_format(#{} = Map, Request) ->
	map_to_format(Map, format_list(Request, Map));
map_to_format(#{} = Map, FormatList) ->
	lists:foldl(
		fun({K, V}, {Acc, MaxKeySize}) ->
			Format = #format{name = PrKey} =
				case lists:keyfind(K, #format.key, FormatList) of
					#format{name = []} = F -> F#format{name = K};
					#format{} = F -> F;
					_ -> #format{key = K, name = K}
				end,
			{Acc ++ [Format#format{value = map_to_format(V, FormatList)}],
				case MaxKeySize < byte_size(PrKey) of
					true -> byte_size(PrKey);
					_ -> MaxKeySize
				end}
		end, {[], 0}, maps:to_list(Map));
map_to_format(Value, _) ->
	Value.

-spec offset(integer(), list(#message_entity{}) | #message_entities{} | #bot{}) -> list(#message_entity{}).
offset(0, Item) ->
	Item;
offset(Offset, #message_entity{offset = Offset2} = Entity) ->
	Entity#message_entity{offset = Offset2 + Offset};
offset(Offset, #message_entities{items = Es} = Entities) ->
	Entities#message_entities{items = offset(Offset, Es)};
offset(Offset, [H | T]) ->
	[offset(Offset, H) | offset(Offset, T)];
offset(_Offset, El) ->
	El.

-spec reply_to_text(summary | position | user | binary(), map()) -> {binary(), list(message_entity())}.
reply_to_text(Request, #{} = Map) ->
	reply_to_text(Request, Map, []).

-spec reply_to_text(summary | position | user | binary(), map(), [] | [all]) -> {binary(), list(message_entity())}.
reply_to_text(Request, #{} = Map, Options) ->
	{Text, Entities} = map_to_text(Request, Map, Options),
	Header = header(Request),
	{<<Header/binary, $\n, (iolist_to_binary(Text))/binary>>,
		[entity(header, Header) | offset(byte_size(Header) + 1, Entities)]}.

-spec map_to_text(summary | position | user | binary(), map()) -> {binary(), list(message_entity())}.
map_to_text(Request, #{} = Map) ->
	map_to_text(Request, Map, []).

-spec map_to_text(summary | position | user | binary(), map(), [] | [all]) -> {binary(), list(message_entity())}.
map_to_text(Request, #{} = Map, []) ->
	do_text(fill_format_list(Request, Map));
map_to_text(Request, #{} = Map, [all]) ->
	do_text(map_to_format(Map, Request)).

-spec format_stats(map(), binary()) -> {string(), {string(), list(message_entity())}}.
format_stats(StatsMaps, <<"all">>) ->
	lists:foldl(
		fun(Total, Acc) ->
			format_stats(StatsMaps, Total, Acc)
		end, {[], []}, [<<"24h">>, <<"7d">>, <<"30d">>]);
format_stats(StatsMaps, Total) ->
	format_stats(StatsMaps, Total, {[], []}).

-spec format_stats(map(), binary(), {string(), list(message_entity())}) -> {string(), {string(), list(message_entity())}}.
format_stats(StatsMaps, Total, {Str, Entities}) ->
	Header = header(tv, Total),
	UserMaps = [User#{<<"currency">> => Cur} || #{<<"currency">> := Cur, <<"user">> := User} <- StatsMaps],
	Headings =
		[fun(_) -> {<<"currency">>, <<"Settlement:">>} end |
		[fun(Cur) -> {iolist_to_binary(io_lib:format(K, [str:to_lower(Cur), Total])), V} end ||
			{K, V} <- [{"volume.future.~s.~s", <<"Futures">>},
						{"volume.future.~s_usd.~s", <<"Futures ($)">>},
						{"volume.option.~s.~s", <<"Options">>}]]], %% set correct order
	Currencies =
		[{<<"btc">>, <<"Bitcoin:">>},
		{<<"eth">>, <<"Ethereum:">>},
		{<<"usdc">>, <<"USDC:">>},
		{<<"sol">>, <<"Solana:">>}],

	HEs =
		lists:foldl(
			fun(HeadFun, {Str2, Es}) ->
				{_, V} = HeadFun(<<>>),
				{Str2 ++ binary_to_list(V) ++ lists:duplicate(?TV_COL_SIZE - byte_size(V), $\s), Es ++ [entity(tv_key, ?TV_COL_SIZE, Str2)]}
			end, {Str ++ Header, Entities ++ [entity(header, Header, Str)]}, Headings),

	lists:foldl(
		fun(#{<<"currency">> := Cur} = UserMap, Acc) ->
			lists:foldl(
				fun(HeadFun, {Str2, Es2}) ->
					{Val, EntityKey} =
						case HeadFun(Cur) of
							{<<"currency">> = K, _} ->
								#{K := V} = UserMap,
								{binary_to_list(<<$\n, (proplists:get_value(str:to_lower(V), Currencies, V))/binary>>), tv_key};
							{K, _} ->
								{format(maps:get(K, UserMap)), tv_value}
						end,
					{Str2 ++ Val ++ lists:duplicate(?TV_COL_SIZE - length(Val), $\s), Es2 ++ [entity(EntityKey, ?TV_COL_SIZE, Str2)]}
				end, Acc, Headings)
		end, HEs, UserMaps).

-spec help_header(private | public | custom, list()) -> [] | [string() | list({string(), list(message_entity())})].
help_header(_Type, []) -> [];
help_header(private, CmdStr) -> [?PRIV_CMDS, CmdStr];
help_header(public, CmdStr) -> [?PUB_CMDS, CmdStr];
help_header(custom, CmdStr) -> [?CUSTOM_CMDS, CmdStr].

-spec help_format(#cmd{} | all | moderator | admin | list(all | moderator | admin)) -> list({string(), list(message_entity())}).
help_format(#cmd{name = Name, default = [help | _]}) ->
	help_merge([?HELP_HEAD(Name), ?PRIV_CMDS] ++
		case mnesia:dirty_read(eims_cmd, Name) of
			[#eims_cmd{broadcast = false} = Cmd] ->
				[format_cmd(Cmd)];
			[#eims_cmd{broadcast = true} = Cmd] ->
				[format_cmd(Cmd), ?PUB_CMDS, format_cmd(Cmd, <<"/!">>)]
		end);
help_format(Acl) ->
	help_format(Acl, help_pred_fun(<<"dummy">>)).

help_pred_fun(#message{to = #jid{luser = Room}}) ->
	help_pred_fun(Room);
help_pred_fun(Room) when is_binary(Room) ->
	RoomAccess = case Room of <<"rfq.", _/binary>> -> rfq; _ -> common end,
	fun(Name) ->
		case lists:keyfind(Name, #cmd.name, mod_eims_admin:cmds()) of
			#cmd{name = ?rfq_req} when RoomAccess == common -> false; %% TODO temporary exclude rfq_req command
			#cmd{room_access = #{RoomAccess := true}} -> true;
			#cmd{} -> false;
			false -> true %% for custom commands
		end
	end.

help_format(Acl, PredFun) when is_atom(Acl) ->
	help_format(lists:reverse(lists:dropwhile(fun(El) -> El /= Acl end, [admin, moderator, all])), PredFun);
help_format([_ | _] = Acls, PredFun) ->
	help_format(Acls, lists:flatten([mnesia:dirty_read(eims_cmd, Key) ||
		Key <- mnesia:dirty_all_keys(eims_cmd), PredFun(Key)]), [[], [], []]).

-spec help_format(list(all | moderator | admin), list(#eims_cmd{}), list({string(), list(message_entity())})) -> list({string(), list(message_entity())}).
help_format([], _, Cmds) ->
	help_merge([?HELP_HEAD(?help) | [help_header(Type, TypedCmds) || {Type, TypedCmds} <- lists:zip([private, public, custom], Cmds)]]);
help_format([H | T] = Acls, Cmds, Acc) ->
	Acc2 = lists:foldl(
		fun(#eims_cmd{cmd = ?help, acl = Acl, type = base} = Cmd, [PrivCmds, PubCmds, CustomCmds]) when Acl == H, T /= [] ->
				[[format_cmd(Cmd, <<"//">>) | PrivCmds], PubCmds, CustomCmds]; %% TODO parse doc field to markup
			(#eims_cmd{cmd = ?help}, Tokens) ->
				Tokens;
			(#eims_cmd{cmd = Name, broadcast = Broadcast, acl = Acl, type = base} = Cmd, [PrivCmds, PubCmds, CustomCmds]) when Acl == H ->
				case {lists:keyfind(Name, #cmd.name, mod_eims_admin:cmds()), Broadcast} of
					{false, _} -> Acc;
					{#cmd{default = [help | _]} = Cmd2, _} ->
						[PrivCmds ++ [format_cmd(Cmd2)], PubCmds, CustomCmds];
					{#cmd{}, false} ->
						[PrivCmds ++ [format_cmd(Cmd)], PubCmds, CustomCmds];
					{#cmd{}, true} ->
						[PrivCmds ++ [format_cmd(Cmd)], PubCmds ++ [format_cmd(Cmd, <<"/!">>)], CustomCmds]
				end;
			(#eims_cmd{doc = _Doc, acl = Acl, type = custom} = Cmd, [PrivCmds, PubCmds, CustomCmds]) when Acl == H, Acls /= [all] ->
				[PrivCmds, PubCmds, CustomCmds ++ [format_cmd(Cmd)]];
			(#eims_cmd{}, Tokens) ->
				Tokens
		end, Acc, Cmds),
	help_format(T, Cmds, Acc2).

-spec format_cmd(#eims_cmd{}) -> {string(), list(message_entity())}.
format_cmd(#eims_cmd{} = Cmd) ->
	format_cmd(Cmd, <<"/">>);
format_cmd(#cmd{} = Cmd) ->
	format_cmd(Cmd, <<"/">>).

-spec format_cmd(#eims_cmd{}, binary()) -> {string(), list(message_entity())}.
format_cmd(#cmd{name = Name, default = [help | _]}, Prefix) ->
	Doc = <<" = ", (cmd(Name))/binary, " help">>,
	cmd_entities(<<Prefix/binary, Name/binary, Doc/binary>>, Prefix, Name, Doc);
format_cmd(#eims_cmd{cmd = Name, doc = Doc, type = custom, out = Out}, Prefix) when Doc == <<>>; is_atom(Doc) ->
	Doc2 = <<" = ", Out/binary>>,
	cmd_entities(<<Prefix/binary, Name/binary, Doc2/binary>>, Prefix, Name, Doc2);
format_cmd(#eims_cmd{cmd = Name, doc = Doc, type = custom}, Prefix) ->
	Doc2 = <<" = ", Doc/binary>>,
	cmd_entities(<<Prefix/binary, Name/binary, Doc2/binary>>, Prefix, Name, Doc2);
format_cmd(#eims_cmd{cmd = ?upd, doc = Doc, type = base}, Prefix) ->
	cmd_entities(<<Prefix/binary, ?upd/binary, Doc/binary>>, Prefix, ?upd, Doc);
format_cmd(#eims_cmd{cmd = Name, doc = Doc, type = base}, Prefix) ->
	Doc2 = <<" ", Doc/binary>>,
	cmd_entities(<<Prefix/binary, Name/binary, Doc2/binary>>, Prefix, Name, Doc2).

-spec cmd_entities(binary(), binary(), binary(), binary()) -> {string(), list(message_entity())}.
cmd_entities(Text, Prefix, Name, Doc) ->
	Command = <<Prefix/binary, Name/binary>>,
	{Text, [entity(command, Command), entity(command_doc, Doc, byte_size(Command))]}.

-spec help_merge(list({string(), list(message_entity())})) -> {string(), list(message_entity())}.
help_merge(Cmds) ->
	lists:foldl(
		fun({S, Entities}, {SAcc, EntitiesAcc}) ->
			{<<SAcc/binary, S/binary, "\n">>, EntitiesAcc ++ offset(byte_size(SAcc), Entities)};
			(S, {SAcc, EntitiesAcc}) ->
				SAcc2 = <<SAcc/binary, S/binary, "\n">>,
				{SAcc2, EntitiesAcc ++ [entity(header, S, byte_size(SAcc))]}
		end, {<<>>, []}, lists:flatten(Cmds)).

