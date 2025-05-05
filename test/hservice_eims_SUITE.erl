-module(hservice_eims_SUITE).
-compile(export_all).

-include_lib("escalus/include/escalus.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("exml/include/exml.hrl").
-include_lib("xmpp/include/xmpp_codec.hrl").
-include_lib("xmpp/include/ns.hrl").
-include_lib("ejabberd/include/mod_mam.hrl").
-include("../include/eims.hrl").

-include("../include/deribit_fields.hrl").


-import(eims, [wait_for_result/2, wait_for_result/4, wait_for_list/1, wait_for_list/2, wait_for_stanzas/2,
					wait_for_stanzas/3, wait_for_stanza/1, wait_for_stanza/2, send/2]).
-import(ct_helper, [config/2, doc/1]).

-define(a(Condition), ?assert(Condition)).
-define(b(Cmd), Cmd/binary).

%% API

%%--------------------------------------------------------------------
%% Suite configuration
%%--------------------------------------------------------------------

all() ->
	[{group, main}].

groups() ->
	MainSequence = ct_helper:all(?MODULE),
	[{main, [sequence], MainSequence}, {local, [sequence], MainSequence -- [eims_badwords_story]}].

init_per_suite(Config) ->
	[escalus:Fun([{escalus_user_db, {module, escalus_ejabberd}} | Config], escalus_users:get_users([alice, david])) || Fun <- [delete_users, create_users]],
	[begin
		 OldV = application:get_env(ejabberd, K, V),
		 application:set_env(ejabberd, K, ?MODULE),
		 {K, OldV}
	 end || {K, V} <- do_env_vars()] ++ Config.

end_per_suite(Config) ->
%%	escalus:delete_users([{escalus_user_db, {module, escalus_ejabberd}} | Config], escalus_users:get_users([alice])),
	[application:set_env(ejabberd, Key, proplists:get_value(Key, Config, Val)) || {Key, Val} <- do_env_vars()],
	Config.

init_per_group(_GroupName, Config) ->
	Config.

end_per_group(_GroupName, Config) ->
	Config.


init_per_testcase(hserv_token_story, Config) ->
	Intervals = [{K, application:get_env(ejabberd, K, V)} || {K, V} <-
		[{refresh_token_interval, 800}, {access_token_interval, 90}]],
	application:set_env(ejabberd, refresh_token_interval, 2),
	application:set_env(ejabberd, access_token_interval, 1),
	init_per_testcase(admin_eims_story, Intervals ++ Config);
init_per_testcase(CaseName, Config) ->
	Config2 = escalus:init_per_testcase(CaseName, Config),
	meck:new(eims, [no_link, passthrough, unstick]),
	meck:expect(mod_muc_opt, min_message_interval, fun (_) -> proplists:get_value(min_message_interval, Config2, 0) end),
	[Host, RoomHost, Rooms, Users] =
		[escalus_ct:get_config(K) || K <- [ejabberd_domain, room_host, eims_rooms, escalus_users]],
	[begin
		 Node = config(username, UserData),
		 Server = config(server, UserData),
		 mnesia:dirty_delete(eims_storage, {Node, Server})
	 end || {_, UserData} <- Users],
	[begin
		 [Room, RoomOpts, Affs] = [config(K, Opts) || K <- [name, options, affiliations]],
		 catch mod_muc_admin:destroy_room(Room, RoomHost),
		 ok = wait_for_result(fun() -> catch mod_muc_admin:create_room_with_opts(Room, RoomHost, Host, RoomOpts) end, ok), %% TODO add affiliations in room options
		 [begin
			  UserCfg = config(U, Users),
			  Jid = jid:to_string(list_to_tuple([config(K, UserCfg) || K <- [username, server]] ++ [<<>>])),
			  ok = mod_muc_admin:set_room_affiliation(Room, RoomHost, Jid, atom_to_binary(Aff))
		  end || {U, Aff} <- Affs]
	 end || {_, Opts} <- Rooms],
	case proplists:get_value(drop_token, Config, true) of
		true -> [eims:drop_tokens(jid:decode(escalus_users:get_jid(Config, User))) || {User, _} <- Users];
		_ -> ok
	end,
	meck:new(httpc, [no_link, passthrough, unstick]),
	meck:new(acl, [no_link, passthrough]),
	meck:expect(httpc, request, fun do_request/4),
	meck:expect(acl, match_rule, fun do_match_rule/3),
	Config2.

end_per_testcase(eims_custom_story, Config) ->
	[mnesia:dirty_delete(eims_cmd, Cmd) || Cmd <- [<<"test_text">>, <<"test_custom">>]],
	end_per_testcase(hserv_eims_story, Config);
end_per_testcase(eims_token_story, Config) ->
	[application:set_env(ejabberd, K, config(K, Config))
		|| K <- [refresh_token_interval, access_token_interval]],
	application:set_env(ejabberd, refresh_token_http_code, 200),
	end_per_testcase(hserv_eims_story, Config);
end_per_testcase(CaseName, Config) ->
	meck:unload(),
	escalus:end_per_testcase(CaseName, Config).

%%--------------------------------------------------------------------
%% admin EIMS tests
%%--------------------------------------------------------------------

hserv_eims_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick, _ClaraNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob, clara]],
	_WhaleNodes = [BobNode, ClaraNode] = [escalus_config:get_ct({escalus_users, U, username}) || U <- [bob, clara]],
	_WhalePwds = [_BobPwd, _ClaraPwd] = [escalus_config:get_ct({escalus_users, U, password}) || U <- [bob, clara]],
	[Room, RoomHost] = binary:split(RoomJid, <<"@">>),
	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}, {clara, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob,
			#client{jid = ClaraJid} = _Clara) ->
			Jids = [AliceJid, BobJid],
			[_AliceNode, BobNode, ClaraNode] = Nodes = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid, ClaraJid]],
			[[_], [], []] = [mnesia:dirty_read(passwd, {Node, Host}) || Node <- Nodes],
			%% Alice has no token and Bob has token
			[{error, token_not_found}, BobNode] = [eims_rest:get_access_token(jid:decode(Jid)) || Jid <- Jids],

			%% Alice enter to ChatRoom
			do_enter_room(Alice, RoomJid, AliceNick),
			%% Alice sends a message to ChatRoom
			escalus:wait_for_stanza(Alice), %% Alice wait for presence from ChatRoom
			send(Alice, HelloPkt = escalus_stanza:groupchat_to(RoomJid, <<"HELLO ALL!">>)),

			%% Alice gets the message from ChatRoom
			escalus:assert(is_groupchat_message, [<<"HELLO ALL!">>], escalus:wait_for_stanza(Alice)),

			HackerPkt = xmpp:set_subtag(xmpp:decode(HelloPkt), #bot{hash = <<"hacker_hash">>}), %% hacker message with bot subtag
			send(Alice, HackerPkt), %% Alice sends hacker message
			#message{body = [#text{data = <<"Message forbidden">>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),

			%% Bob enter to ChatRoom
			do_enter_room(Bob, RoomJid, BobNick),
			%% Bob sends a message to ChatRoom
			[_, _] = wait_for_list(fun() -> mod_muc_admin:get_room_occupants(Room, RoomHost) end, 2),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"HELLO!">>)),
			escalus_client:wait_for_stanzas(Bob, 3), %% Bob wait for 3 presence from ChatRoom

			%% Bob gets the message from ChatRoom
			escalus:assert(is_groupchat_message, [<<"HELLO!">>], escalus:wait_for_stanza(Bob)),
			escalus_client:wait_for_stanzas(Alice, 1), %% Bob wait for 3 presence from ChatRoom
			escalus:assert(is_groupchat_message, [<<"HELLO!">>], escalus:wait_for_stanza(Alice)),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"TEST">>)),
			{_, NewBobNick, _} = lists:keyfind(BobJid, 1, mod_muc_admin:get_room_occupants(Room, RoomHost)), %% get "whale" nick
			%% Bob and Alice gets the message TEST from ChatRoom
			Clients = [Bob, Alice],
			[escalus:assert(is_groupchat_message, [<<"TEST">>], escalus:wait_for_stanza(Client)) || Client <- Clients],

			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?user), " alice">>)), %% access denied for Bob
			escalus:assert(is_groupchat_message, [<<"ERROR: Access denied">>], escalus:wait_for_stanza(Bob)),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/invalid_cmd">>)),
			[#xmlel{} = InvalidMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"Invalid /invalid_cmd command">>}]} = xmpp:decode(InvalidMsg),

			%% get Bob data if Bob in room
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?user), " ", NewBobNick/binary>>)),
			[#xmlel{} = UserMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"\t", _/binary>> = UserData}]} = xmpp:decode(UserMsg),

			%% get Bob data if Bob is out of the room
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?kick), " fakenick">>)),
			escalus:assert(is_groupchat_message, [<<"User \"fakenick\" not found in this groupchat">>], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?kick), " ", NewBobNick/binary>>)),
			escalus:assert(is_presence_with_type, [<<"unavailable">>], escalus:wait_for_stanza(Alice)),
			[{_, AliceNick, _}] = wait_for_list(fun() -> mod_muc_admin:get_room_occupants(Room, RoomHost) end, 1),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?user), " ", NewBobNick/binary>>)),

			[_, #xmlel{name = <<"message">>} = UserMsg2] = escalus:wait_for_stanzas(Alice, 2),
			#message{body = [#text{data = <<"\t", _/binary>> = UserData}]} = xmpp:decode(UserMsg2),
			do_enter_room(Bob, RoomJid, <<"bob">>),
			escalus_client:wait_for_stanzas(Bob, 7),
			escalus_client:wait_for_stanzas(Alice, 1),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?purge), " ", NewBobNick/binary>>)),
			[[_, _] = escalus:wait_for_stanzas(Client, 2) || Client <- Clients], %% 2 retract messages
			PurgeSuccessMsg = <<NewBobNick/binary, " messages have been deleted successfully">>,
			escalus:assert(is_groupchat_message, [PurgeSuccessMsg], escalus:wait_for_stanza(Alice)),

			[_] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end, 1),
			[_] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end, 1),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"PURGE TEST BY JID">>)),
			{_, NewBobNick, _} = lists:keyfind(BobJid, 1, mod_muc_admin:get_room_occupants(Room, RoomHost)), %% get "whale" nick
			%% Bob and Alice gets the message "PURGE TEST" from ChatRoom
			[escalus:assert(is_groupchat_message, [<<"PURGE TEST BY JID">>], escalus:wait_for_stanza(Client)) || Client <- Clients],
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?purge), " ", BobJid/binary>>)), %% purge by nick
			[escalus:wait_for_stanzas(Client, 1) || Client <- Clients], %% 1 retract messages
			PurgeSuccessMsg2 = <<BobJid/binary, " messages have been deleted successfully">>,
			escalus:assert(is_groupchat_message, [PurgeSuccessMsg2], escalus:wait_for_stanza(Alice)),
			[_] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end, 1),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?purge), " all">>)),
			[escalus:wait_for_stanzas(Client, 1) || Client <- [Bob, Alice]], %% 1 retract messages
			PurgeAllSuccessMsg = <<"all messages have been deleted successfully">>,
			escalus:assert(is_groupchat_message, [PurgeAllSuccessMsg], escalus:wait_for_stanza(Alice)),
			[] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end),
			[] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end),


			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"delete message by id!">>)),
			W = #xmlel{name = <<"message">>, children = [#xmlel{attrs = [_, {<<"id">>, Id} | _]} | _]} %% get id from history
				= escalus:wait_for_stanza(Bob),
			escalus:assert(is_groupchat_message, [<<"delete message by id!">>], W),
			escalus:wait_for_stanzas(Alice, 1),

			IntId = binary_to_integer(Id),
			[#message{meta = #{stanza_id := IntId}, body = [#text{data = <<"delete message by id!">>}]}] =
				eims:select_history({Room, RoomHost}),
			eims:edit_history_msg(Room, RoomHost, Host, binary_to_integer(Id), EditText = <<"edit message by id!">>),

			[#message{meta = #{stanza_id := IntId}, body = [#text{data = <<"edit message by id!">>}]}] =
				eims:select_history({Room, RoomHost}),

			#archive_msg{packet = EditMsg} = eims_db:edit_mam_msg_by_id({Room, RoomHost}, Id, EditText),
			#message{body = [#text{data = EditText}]} = xmpp:decode(EditMsg),
			#archive_msg{packet = GetMsg} =
				wait_for_result(fun() -> eims_db:get_mam_msg_by_id({Room, RoomHost}, Id) end, fun(#archive_msg{}) -> true; (_) -> false end),
			EditMsg = #message{body = [#text{data = _Text}]} = xmpp:decode(GetMsg),

			NewEditTxt = <<"new edit message text">>,
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?edit), " ", NewEditTxt/binary>>)),
			#archive_msg{} = eims_db:get_last_msg({Room, RoomHost}, NewBobNick),
			EditMsgs = [escalus:wait_for_stanza(Client) || Client <- Clients],
			[true = xmpp:has_subtag(xmpp:decode(ReplaceMsg), Tag) || Tag <- [#chatstate{type = active}, #replace{}, #origin_id{}], ReplaceMsg <- EditMsgs],
			#origin_id{id = _OriginId} = xmpp:get_subtag(xmpp:decode(hd(EditMsgs)), #origin_id{}),

			[#message{meta = #{stanza_id := IntId}, body = [#text{data = NewEditTxt}]}] =
				eims:select_history({Room, RoomHost}),

			#archive_msg{packet = NewEditPkt} = eims_db:get_mam_msg_by_id({Room, RoomHost}, Id),
			#message{body = [#text{data = NewEditTxt}]} = xmpp:decode(NewEditPkt),

			%% remove manually messages from archive and history
			eims:delete_from_history_by_id(Room, RoomHost, Host, [binary_to_integer(Id)]),
			eims_db:remove_mam_msg_by_ids(Room, RoomHost, [Id]),
			[] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end),
			[] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end),

			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"lastmsg del test">>)),
			escalus:assert(is_groupchat_message, [<<"lastmsg del test">>], escalus:wait_for_stanza(Bob)),
			escalus:wait_for_stanzas(Alice, 1),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?del)>>)),
			ApplyMsgs = [escalus:wait_for_stanza(Client) || Client <- Clients],
			[true = xmpp:has_subtag(xmpp:decode(ApplyMsg), Tag) || Tag <- [#fasten_apply_to{}, #hint{type = store}], ApplyMsg <- ApplyMsgs],
			[] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end),
			[] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end),

			[#eims_cmd{stats = HelpStats}] = mnesia:dirty_read(eims_cmd, ?help),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?help)>>)),
			HelpPkt = #message{body = [#text{data = <<"help triggered", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Bob)),
			HelpStats2 = HelpStats + 1,
			[#eims_cmd{stats = HelpStats2}] = mnesia:dirty_read(eims_cmd, ?help),

			#message_entities{items = [#message_entity{} | _]} = xmpp:get_subtag(HelpPkt, #message_entities{}),
			[#eims_cmd{stats = TvStats}] = mnesia:dirty_read(eims_cmd, ?tv),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?tv), " 24h">>)),
			#message{body = [#text{data = <<"\nMy", _/binary>>}]} = TvMsg = xmpp:decode(escalus:wait_for_stanza(Bob)),
			TvStats2 = TvStats + 1,
			[#eims_cmd{stats = TvStats2}] = mnesia:dirty_read(eims_cmd, ?tv),
			#bot{hash = <<>>} = xmpp:get_subtag(TvMsg, #bot{}),

			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/!", ?b(?tv), " 24h">>)),
			BotTag = eims:bot_tag(),
			[begin
				 #message{body = [#text{data = <<"from ", _/binary>>}]} = TvPkt2 = xmpp:decode(escalus:wait_for_stanza(Client)),
				 [true, false, true] = [xmpp:has_subtag(TvPkt2, Tag) || Tag <- [BotTag, #hint{type = 'no-store'}, #message_entities{}]]
			 end || Client <- Clients],
			[_] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end, 1),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?position)>>)),
			PositionPkt = #message{body = [#text{data = <<"position triggered", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Bob)),
			BotTag = #bot{hash = <<>>}= xmpp:get_subtag(PositionPkt, #bot{}),
			#message_entities{items = [#message_entity{} | _]} = xmpp:get_subtag(PositionPkt, #message_entities{}),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?position), " invalid">>)),
			#message{body = [#text{data = <<"Invalid", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Bob)),

			[#eims_cmd{stats = PositionStats}] = mnesia:dirty_read(eims_cmd, ?position),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/!", ?b(?position), " BTC-PERPETUAL">>)),
			[begin
				 #message{body = [#text{data = <<"from ", _/binary>>}]} = DecPosMsg2 = xmpp:decode(escalus:wait_for_stanza(Client)),
				 [true, true, false] = [xmpp:has_subtag(DecPosMsg2, Tag) || Tag <- [#message_entities{}, BotTag, #hint{type = 'no-store'}]]
			 end || Client <- Clients],
			[_, _] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end, 2),
			PositionStats2 = PositionStats + 1,
			[#eims_cmd{stats = PositionStats2}] = mnesia:dirty_read(eims_cmd, ?position),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?stats)>>)),
			#message{body = [#text{data = <<"Command stats for whale. users:", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),
			ok
		end).

hserv_token_story(Config) ->
	RoomJid = do_test_room_jid(),
	Host = escalus_config:get_ct(ejabberd_domain),
	_Nicks = [AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	_Nodes = [_AliceNode, BobNode] = [escalus_config:get_ct({escalus_users, U, username}) || U <- [alice, bob]],
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			#xmlel{name = <<"eims">>} = eims:get_from_private(BobJID = jid:decode(BobJid)),
			{BobNode, _, _} = jid:split(BobJID),
			BobAccessToken = BobNode = eims_rest:get_access_token(BobJID),
			T1 = erlang:system_time(millisecond),
			NewBobToken = wait_for_result(fun() -> eims_rest:get_access_token(BobJID) end, fun(Arg) when Arg == BobAccessToken -> false; (_) -> true end),
			?assert(NewBobToken /= BobAccessToken), %% verify refresh token for Bob
			T2 = erlang:system_time(millisecond),
			?assert(T2 - T1 > 1000), %% take a new token in a second

			#message{from = BotComponentJID, body = []} = TokenPkt = xmpp:decode(escalus:wait_for_stanza(Bob)), %% send token to client
			#message_payload{datatype = ?NS_TOKEN_TYPE, json = #payload_json{data = Json}} = xmpp:get_subtag(TokenPkt, #message_payload{}),
			#{<<"access_token">> := NewBobToken, <<"refresh_token">> := _RefreshToken} = jiffy:decode(Json, [return_maps]),
			application:set_env(ejabberd, refresh_token_http_code, 400),
			{error, bad_request, _Error} = wait_for_result(fun() -> eims_rest:get_access_token(BobJID) end,
				fun({error, bad_request, _Error}) -> true; (_) -> false end),
			?assert(erlang:system_time(millisecond) - T2 > 1000),
			do_enter_room(Bob, RoomJid, BobNick),
			[_] = escalus:wait_for_stanzas(Bob, 1),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?position), " BTC-PERPETUAL">>)),
			escalus:assert(is_groupchat_message, [<<"Token refresh failed">>], escalus:wait_for_stanza(Bob)),
			escalus_client:stop(Config, Bob),
			[] = eims:get_tokens(BobJID),

			application:set_env(ejabberd, refresh_token_http_code, 200),
			do_enter_room(Alice, RoomJid, AliceNick),
			escalus:wait_for_stanzas(Alice, 1),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?hserv_auth)>>)),
			#message{body = [#text{data = <<"https:", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),
			AuthNonce = eims:get_tokens(AliceJID = jid:decode(AliceJid)),
			?assert(is_integer(AuthNonce)),
			UriMap = uri_string:parse(eims_rest:redirect_uri()),
			State = base64:encode(term_to_binary(#{jid => AliceJid, nonce => AuthNonce})),
			Url = uri_string:normalize(UriMap#{query => uri_string:compose_query([{"code", "hahscode"}, {"state", State}])}),
			{ok, {{_, 200, "OK"}, _, "\"ok\""}} = httpc:request(get, {Url, []}, [], []),
			AccessToken = eims_rest:get_access_token(AliceJID),
			?assert(is_binary(AccessToken)),
			T4 = erlang:system_time(millisecond),
			NewAliceToken = wait_for_result(fun() -> eims_rest:get_access_token(AliceJID) end,
											fun(Arg) when Arg == AccessToken -> false; (_) -> true end),
			?assert(NewAliceToken /= AccessToken), %% verify refresh token for Bob
			?assert(erlang:system_time(millisecond) - T4 > 1000), %% take a new token in a second
			[#message{from = BotComponentJID}, #message{from = BotComponentJID}] =
				[xmpp:decode(P)|| P <- escalus:wait_for_stanzas(Alice, 2)],
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?position), " BTC-PERPETUAL">>)),
			[AliceSummaryMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"\nPosition:", _/binary>>}]} = xmpp:decode(AliceSummaryMsg),
			escalus_client:stop(Config, Alice),
			[] = eims:get_tokens(AliceJID)
		end).


hserv_custom_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			Clients = [Alice, Bob],
			do_enter_room(Alice, RoomJid, AliceNick),
			do_enter_room(Bob, RoomJid, BobNick),
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],

			CustomCmd = <<"test_custom">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary, " /tv 7d">>)),
			escalus:assert(is_groupchat_message, [?UPD_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", CustomCmd/binary>>)),
			[TvMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"Token", _/binary>>}]} = xmpp:decode(TvMsg),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?DEL_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),
			[] = wait_for_list(fun() -> mnesia:dirty_read(eims_cmd, CustomCmd) end),

			TextCmd = <<"test_text">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", TextCmd/binary, " TEXT!">>)),
			escalus:assert(is_groupchat_message, [?UPD_TEXT(TextCmd)], escalus:wait_for_stanza(Alice)),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", TextCmd/binary>>)),
			escalus:assert(is_groupchat_message, [<<"TEXT!">>], AlicePkt = escalus:wait_for_stanza(Alice)),
			true = xmpp:has_subtag(xmpp:decode(AlicePkt), #origin_id{}),
			escalus:wait_for_stanzas(Bob, 1),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", TextCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?DEL_TEXT(TextCmd)], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary, " /position BTC-PERPETUAL">>)),
			escalus:assert(is_groupchat_message, [?UPD_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),

			HelpCmd = <<"summary help">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?help), " ", CustomCmd/binary, " ", HelpCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?CUSTOM_UPD_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),
			[#eims_cmd{doc = HelpCmd}] = mnesia:dirty_read(eims_cmd, CustomCmd),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?help), " ", CustomCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?CUSTOM_DEFAULT_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),
			[#eims_cmd{doc = undefined}] = mnesia:dirty_read(eims_cmd, CustomCmd),


			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", CustomCmd/binary>>)),
			escalus:assert(is_groupchat_message, [<<"ERROR: Access denied">>], escalus:wait_for_stanza(Bob)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?DEL_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary, " /other">>)),
			escalus:assert(is_groupchat_message, [?CUSTOM_INCLUDE_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", ?b(?tv), " fake text">>)),
			escalus:assert(is_groupchat_message, [?CUSTOM_BASE_TEXT(?tv)], escalus:wait_for_stanza(Alice)),
			ok
		end).

do_summary() ->
	#{<<"options_gamma">> => 0.0, <<"equity">> => 0.0,
		<<"available_withdrawal_funds">> => 0.0,
		<<"creation_timestamp">> => 1671568818192,
		<<"margin_balance">> => 0.0, <<"total_pl">> => 0.0,
		<<"portfolio_margining_enabled">> => false,
		<<"projected_delta_total">> => 0.0,
		<<"spot_reserve">> => 0.0, <<"available_funds">> => 0.0,
		<<"email">> => <<"cryoflamer@ukr.net">>,
		<<"projected_initial_margin">> => 0.0,
		<<"estimated_liquidation_ratio_map">> => #{},
		<<"balance">> => 0.0, <<"options_pl">> => 0.0,
		<<"options_delta">> => 0.0,
		<<"interuser_transfers_enabled">> => false,
		<<"username">> => <<"cryoflamer2">>,
		<<"options_theta">> => 0.0, <<"referrer_id">> => null,
		<<"options_session_upl">> => 0.0,
		<<"futures_session_upl">> => 0.0,
		<<"system_name">> => <<"cryoflamer2">>,
		<<"session_rpl">> => 0.0, <<"options_vega">> => 0.0,
		<<"projected_maintenance_margin">> => 0.0,
		<<"security_keys_enabled">> => false,
		<<"options_value">> => 0.0, <<"currency">> => <<"BTC">>,
		<<"futures_pl">> => 0.0, <<"initial_margin">> => 0.0,
		<<"type">> => <<"main">>,
		<<"limits">> =>
			#{<<"matching_engine">> =>
				#{<<"burst">> => 20, <<"rate">> => 5},
			 <<"non_matching_engine">> =>
				#{<<"burst">> => 100, <<"rate">> => 20}},
		<<"estimated_liquidation_ratio">> => 0.0,
		<<"fee_balance">> => 0.0, <<"session_upl">> => 0.0,
		<<"delta_total_map">> => #{},
		<<"futures_session_rpl">> => 0.0,
		<<"options_session_rpl">> => 0.0, <<"id">> => 47973,
		<<"delta_total">> => 0.0, <<"maintenance_margin">> => 0.0}.

%% This function is a version of escalus_client:stop/2
%% that ensures that c2s process is dead.
%% This allows to avoid race conditions.
do_logout_user(Config, User) ->
	Resource = escalus_client:resource(User),
	Username = escalus_client:username(User),
	Server = escalus_client:server(User),
	Result = ejabberd_sm:get_session_pid(Username, Server, Resource),
	case Result of
		none ->
			%% This case can be a side effect of some error, you should
			%% check your test when you see the message.
			ct:pal("issue=user_not_registered jid=~ts@~ts/~ts",
				[Username, Server, Resource]),
			escalus_client:stop(Config, User);
		Pid when is_pid(Pid) ->
			MonitorRef = erlang:monitor(process, Pid),
			escalus_client:stop(Config, User),
			%% Wait for pid to die
			receive
				{'DOWN', MonitorRef, _, _, _} ->
					ok
			after 10000 ->
				ct:pal("issue=c2s_still_alive "
				"jid=~ts@~ts/~ts pid=~p",
					[Username, Server, Resource, Pid]),
				ct:fail({logout_user_failed, {Username, Resource, Pid}})
			end
	end.

do_env_vars() ->
	[].

%% Help functions TODO move to escalus_stanza module
do_enter_groupchat(#client{jid = FromJid}, RoomJid, Nick) ->
	#xmlel{name = <<"presence">>,
		attrs = [{<<"from">>, FromJid}, {<<"to">>, <<RoomJid/binary, "/", Nick/binary>>}],
		children = [#xmlel{name = <<"x">>, attrs = [{<<"xmlns">>, ?NS_MUC}]}]}.

do_test_room_jid() ->
	do_room_jid(eims_test).

do_room_jid(Room) ->
	RoomName = escalus_config:get_ct({eims_rooms, Room, name}),
	RoomHost = escalus_ct:get_config(room_host),
	<<RoomName/binary, "@", RoomHost/binary>>.

do_enter_room(Client, RoomJid, Nick) ->
	send(Client, do_enter_groupchat(Client, RoomJid, Nick)),
	escalus_client:wait_for_stanzas(Client, 2). %% Client wait for 2 presences from ChatRoom

do_match_rule(<<"localhost">>, eims_admin, #{usr := {<<"alice">>, <<"localhost">>, <<>>}}) ->
	allow;
do_match_rule(Server, configure, U) ->
	meck:passthrough([Server, eims_admin, U]);
do_match_rule(Host, Access, Match) ->
	meck:passthrough([Host, Access, Match]).

do_send_fun({Jid, OldData}, Interval, Pid) ->
	fun(Data) ->
		NewData = Data + 1,
		OldData = eims:get_tokens(Jid),
		{TRef, _} = eims:send_delay_check({Jid, NewData}, do_send_fun({Jid, NewData}, Interval, Pid), Interval),
		Pid ! {sys_time, calendar:local_time(), NewData, TRef}
	end.
do_receive_delay_msg(BeginSec) ->
	receive
		{sys_time, Time, Data, TRef} when Data > 21 ->
			ct:comment("data: ~p", [Data]),
			Sec = calendar:datetime_to_gregorian_seconds(Time),
			?assert(Sec - BeginSec =< 2),
			erlang:cancel_timer(TRef);
		{sys_time, _Time, Data, _TRef} ->
			ct:comment("data: ~p", [Data]),
			do_receive_delay_msg(BeginSec)
	after 2000 -> ?assert(false)
	end.

do_request(Method, Request, HTTPOptions, []) ->
	case catch do_request(uri_string:parse(element(1, Request)), element(2, Request)) of
		{'EXIT', _} -> meck:passthrough([Method, Request, HTTPOptions, []]);
		Res -> Res
	end.

do_request(#{path := "/api/v2/public/get_trade_volumes"} = MapUri, Headers) ->
	httpc:request(get, {uri_string:normalize(MapUri), Headers}, [], []);
do_request(#{path := "/api/v2/private/get_position", query := "instrument_name=BTC-PERPETUAL"}, _Headers) ->
	Body = jiffy:encode(#{<<"result">> => #{<<"instrument_name">> => <<"BTC-PERPETUAL">>}}),
	{ok, {{[], 200, []}, [], Body}};
do_request(#{path := "/api/v2/private/get_position", query := "instrument_name=" ++ _}, _Headers) ->
	Body = jiffy:encode(
		#{<<"error">> =>
		#{<<"data">> => #{<<"param">> => <<"instrument_name">>,
			<<"reason">> => <<"wrong format">>},
			<<"message">> => <<"Invalid params">>}}),
	{ok, {{[], 400, []}, [], Body}};
do_request(#{path := "/api/v2/private/get_account_summary", query := [{"currency", Currency}, {"extended", "true"}]}, _Headers)
	when Currency == "BTC"; Currency == "ETH" ->
	Body = jiffy:encode(#{<<"result">> =>
	#{<<"email">> => <<"bob@fakeemail.com">>,
		<<"currency">> => list_to_binary(Currency)}}),
	{ok, {{[], 200, []}, [], Body}};
do_request(#{path := "/api/v2/private/get_stats", query := "currency="++_}, _Headers) ->
	Body = jiffy:encode(#{<<"result">> =>
	#{<<"apps">> => [],
		<<"user">> =>
		#{<<"volume.future.btc_usd.2022">> => 0.0,
			<<"commissions.btc.2021">> => 0.0,
			<<"volume.option.btc.30d">> => 0.0,
			<<"volume.future.btc.2021">> => 0.0,
			<<"commissions.btc.30d">> => 0.0,
			<<"volume.future.btc.7d">> => 0.0,
			<<"volume.future.btc_usd.30d">> => 0.0,
			<<"commissions.btc.24h">> => 0.0,
			<<"volume.future.btc_usd.2019">> => 0.0,
			<<"volume.future.btc.24h">> => 0.0,
			<<"volume.option.btc.7d">> => 0.0,
			<<"volume.future.btc_usd">> => 0.0,
			<<"volume.future.btc_usd.7d">> => 0.0,
			<<"volume.future.btc_usd.24h">> => 0.0,
			<<"volume.future.btc.2017">> => 0.0,
			<<"commissions.btc.2022">> => 0.0,
			<<"volume.option.btc.2017">> => 0.0,
			<<"volume.option.btc.24h">> => 0.0,
			<<"volume.future.btc.2019">> => 0.0,
			<<"commissions.btc.2020">> => 0.0,
			<<"volume.future.btc.2022">> => 0.0,
			<<"volume.future.btc.2018">> => 0.0,
			<<"volume.future.btc.2020">> => 0.0,
			<<"volume.future.btc.30d">> => 0.0,
			<<"commissions.btc.2017">> => 0.0,
			<<"volume.future.btc_usd.2020">> => 0.0,
			<<"volume.option.btc.2021">> => 0.0,
			<<"commissions.btc.7d">> => 0.0,
			<<"volume.future.btc_usd.2021">> => 0.0,
			<<"commissions.btc.2019">> => 0.0,
			<<"volume.option.btc.2022">> => 0.0,
			<<"volume.future.btc_usd.2017">> => 0.0,
			<<"volume.future.btc_usd.2018">> => 0.0,
			<<"volume.option.btc">> => 0.0,<<"commissions.btc">> => 0.0,
			<<"volume.option.btc.2018">> => 0.0,
			<<"volume.future.btc">> => 0.0,
			<<"commissions.btc.2018">> => 0.0,
			<<"volume.option.btc.2020">> => 0.0,
			<<"volume.option.btc.2019">> => 0.0}}}),
	{ok, {{[], 200, []}, [], Body}};
do_request(#{path := "/api/v2/private/get_account_summary", query := Query} = MapURI, Headers) ->
	do_request(MapURI#{query => uri_string:dissect_query(Query)}, Headers);
do_request(#{path := "/api/v2/public/auth", query := "grant_type=" ++ _}, _Headers) ->
	HttpCode = application:get_env(ejabberd, refresh_token_http_code, 200),
	{ok, {{[], HttpCode, []}, [], do_get_tokens_body(HttpCode)}};
do_request(#{path := "/api/v2/public/auth"}, _Headers) ->
	HttpCode = application:get_env(ejabberd, refresh_token_http_code, 200),
	{ok, {{[], HttpCode, []}, [], do_get_tokens_body(HttpCode)}};
do_request(#{path := "/api/v2/private/chat_get_account_summary"}, [{"Authorization", "bearer " ++ (UserNode = "whale.clara")}]) ->
	Body = #{<<"result">> := Result} = do_get_eims_storage(UserNode),
	BobResult = Result#{<<"main_account_id">> := 9999, <<"id">> := 8888},
	{ok, {{[], 200, []}, [], jiffy:encode(Body#{<<"result">> := BobResult})}};
do_request(#{path := "/api/v2/private/chat_get_account_summary"}, [{"Authorization", "bearer " ++ (UserNode = "whale.bob")}]) ->
	Body = #{<<"result">> := Result} = do_get_eims_storage(UserNode),
	BobResult = Result#{<<"main_account_id">> := 9999, <<"id">> := 9999},
	{ok, {{[], 200, []}, [], jiffy:encode(Body#{<<"result">> := BobResult})}};
do_request(#{path := "/api/v2/private/chat_get_account_summary"}, [{"Authorization", "bearer " ++ UserNode}]) ->
	Body = jiffy:encode(do_get_eims_storage(UserNode)),
	{ok, {{[], 200, []}, [], Body}}.

do_get_eims_storage("whale." ++ UserStr = UserNode) ->
	User = list_to_binary(UserStr),
	UserNodeBin = list_to_binary(UserNode),
%%	[<<"whale">>, User] = binary:split(UserNodeBin = list_to_binary(UserNode), <<".">>),
	Id = rand:uniform(1000),
	#{<<"result">> =>
	#{<<"system_name">> => User,
		<<"jid_node">> => UserNodeBin,
		<<"nick">> => UserNodeBin,
		<<"email">> => <<User/binary, "@fakemail.com">>,
		<<"main_account_id">> => Id,
		<<"id">> => Id,
		<<"main_system_name">> => User,
		<<"main_email">> => <<User/binary, "@fakemail.com">>,
		<<"roles">> => <<"role1, role2">>}};
do_get_eims_storage(_Token) ->
	User = UserNodeBin = <<"alice">>,
	Id = rand:uniform(1000),
	#{<<"result">> =>
	#{<<"system_name">> => User,
		<<"jid_node">> => UserNodeBin,
		<<"nick">> => UserNodeBin,
		<<"email">> => <<User/binary, "@fakemail.com">>,
		<<"main_account_id">> => Id,
		<<"id">> => Id,
		<<"main_system_name">> => User,
		<<"main_email">> => <<User/binary, "@fakemail.com">>,
		<<"roles">> => <<"role1, role2">>}}.

do_get_tokens_body(400) ->
	jiffy:encode(
		#{<<"error">> =>
		#{<<"data">> => #{<<"param">> => <<"refresh_token">>,
			<<"reason">> => <<"wrong format">>},
			<<"message">> => <<"Token refresh failed">>}});
do_get_tokens_body(200) ->
	jiffy:encode(#{<<"result">> =>
	#{<<"access_token">> => integer_to_binary(rand:uniform(1000)),
		<<"refresh_token">> => integer_to_binary(rand:uniform(1000))}}).

account_summary_example() ->
	#{<<"jsonrpc">> => <<"2.0">>,
		<<"result">> =>
		#{<<"projected_initial_margin">> => 0.032764811698305245,
			<<"balance">> => 100.24074341,
			<<"options_delta">> => 0.0,
			<<"total_pl">> => -0.05880321,
			<<"session_upl">> => -0.00282611,
			<<"email">> => <<"email@gmail.com">>,
			<<"available_funds">> => 100.20513668,
			<<"options_session_rpl">> => 0.0,
			<<"futures_session_upl">> => -0.00282611,
			<<"initial_margin">> => 0.03276481,
			<<"maintenance_margin">> => 0.0252037,
			<<"available_withdrawal_funds">> => 100.20513668,
			<<"options_pl">> => 0.0,
			<<"delta_total">> => 0.208,
			<<"session_rpl">> => -1.58e-5,
			<<"portfolio_margining_enabled">> => true,
			<<"options_theta">> => 0.0,
			<<"futures_session_rpl">> => -1.58e-5,
			<<"type">> => <<"main">>,
			<<"currency">> => <<"BTC">>,
			<<"session_funding">> => -4.115e-5,
			<<"referrer_id">> => null,
			<<"options_vega">> => 0.0,
			<<"id">> => 2,
			<<"options_session_upl">> => 0.0,
			<<"futures_pl">> => -0.05880321,
			<<"equity">> => 100.2379015,
			<<"username">> => <<"Admin_1">>,
			<<"tfa_enabled">> => false,
			<<"margin_balance">> => 100.2379015,
			<<"system_name">> => <<"Admin_1">>,
			<<"projected_maintenance_margin">> => 0.02520370130638865,
			<<"options_gamma">> => 0.0},
		<<"testnet">> => false,<<"usDiff">> => 5061,
		<<"usIn">> => 1574793031032477,<<"usOut">> => 1574793031037538}.
