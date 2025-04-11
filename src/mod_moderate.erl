%%%-------------------------------------------------------------------
%%% @doc
%%% Module implements XEP-0425
%%% @end
%%%-------------------------------------------------------------------
-module(mod_moderate).
-compile(export_all).
-behaviour(gen_mod).
%% API
-export([]).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include("translate.hrl").
-include("mod_muc_room.hrl").
-include("mod_mam.hrl").
-include("eims.hrl").

start(Host, _Opts) ->
	ejabberd_hooks:add(user_receive_packet, Host, ?MODULE, user_receive_packet, 100),
	ejabberd_hooks:add(user_send_packet, Host, ?MODULE, user_send_packet, 100).


stop(Host) ->
	ejabberd_hooks:delete(user_receive_packet, Host, ?MODULE, user_receive_packet, 100),
	ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, user_send_packet, 100).

mod_options(_Host) -> [].

mod_doc() ->
	#{desc => ?T("implement XEP-0425"), opts => []}.

depends(_Host, _Opts) ->
	[].

user_receive_packet({IQ = #iq{type = result, sub_els = [DiscoInfo = #disco_info{identities =
		[#identity{category = <<"conference">>}], features = Features}]}, C2SState}) ->
	{IQ#iq{sub_els = [DiscoInfo#disco_info{features = Features ++ [?NS_MESSAGE_MODERATE, ?NS_REPLY]}]}, C2SState};
user_receive_packet(Packet) ->
	Packet.

user_send_packet({#iq{type = set, from = _From,
	to = #jid{server = <<"conference.", _/binary>> = _RoomHost} = _To,
	sub_els = [#xmlel{name = <<"apply-to">>}]} = Pkt, #{jid := _JID} = C2SState}) ->
	user_send_packet({xmpp:decode_els(Pkt), C2SState});
user_send_packet({#iq{type = set, from = #jid{lserver = Host} = From,
	to = #jid{luser = Room, server = <<"conference.", _/binary>> = RoomHost} = To,
	sub_els = [#fasten_apply_to{id = Id, sub_els = [#message_moderate_21{retract = #retract_id{}, reason = Reason}]} = Apply]} = Pkt, #{jid := _JID} = C2SState}) ->
	case lists:keyfind(jid:encode(From), 1, mod_muc_admin:get_room_occupants(Room, RoomHost)) of
		{_, Nick, "moderator"} ->
			Moderated = #message_moderated_21{by = jid:replace_resource(To, Nick), reason = Reason, retract = #retract_id{}},
			MsgPkt = #message{type = groupchat, from = From, to = To,
				sub_els = [Apply#fasten_apply_to{sub_els = [Moderated]}]},
			{ok, Pid} = mod_muc:unhibernate_room(Host, RoomHost, Room),
			mod_muc_room:route(Pid, MsgPkt),
			ejabberd_router:route(Pkt#iq{type = result, from = To, to = From, sub_els = []}),
			IntId = binary_to_integer(Id),
			eims:delete_from_history_by_id(Room, RoomHost, Host, [IntId]),
			case eims_db:select_by_id(groupchat, {Room, RoomHost}, IntId) of
				[#archive_msg{packet = RetractedPkt}] ->
					spawn(fun() -> eims:retract_upload(#message{from = From, to = To}, xmpp:decode(RetractedPkt)) end),
					eims:delete_from_history_by_id(Room, RoomHost, Host, [IntId]);
				[] ->
					?DEBUG("message whith id = ~s not found", [Id]),
					ok
			end,
			eims_db:remove_mam_msg_by_ids(Room, RoomHost, [Id]),
			{stop, {drop, C2SState}};
		_ ->
			ErrorIq =
				#iq{type = error, from = To, to = From,
					sub_els = [#stanza_error{type = modify, reason = forbidden,
						text = [#text{data = <<"Only moderators are allowed to moderate other participant's messages">>}]}]},
			ejabberd_router:route(ErrorIq),
			{stop, {drop, C2SState}}
	end;
user_send_packet(Packet) ->
	Packet.