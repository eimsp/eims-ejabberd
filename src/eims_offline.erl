-module(eims_offline).
-compile(export_all).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include_lib("stdlib/include/qlc.hrl").
-include("mod_offline.hrl").
-include("eims.hrl").

%% API
-export([]).

start(Host) ->
	ejabberd_hooks:add(offline_message_hook, Host, ?MODULE, offline_store_packet, 40).
stop(Host) ->
	ejabberd_hooks:delete(offline_message_hook, Host, ?MODULE, offline_store_packet, 40).


-spec offline_store_packet({any(), message()}) -> {any(), message()}.
offline_store_packet({Action, #message{} = Packet}) ->
	[Pkt | _] = (eims:tag_decorator([#replace{}, #fasten_apply_to{},
											#mam_result{xmlns = ?NS_MAM_2}, #mam_result{xmlns = ?NS_MAM_0}, #mam_result{xmlns = ?NS_MAM_1}],
										[Packet, Action], ?MODULE, offline_packet))(),
	{Action, Pkt}.

offline_packet(#replace{id = OriginId}, [Packet = #message{body = Body}, Action]) ->
	case get_offline_msgs_by_tags([#origin_id{id = OriginId}]) of
		[#offline_msg{packet = Pkt} = OffMsg] ->
			Pkt2 = xmpp:encode((xmpp:decode(Pkt))#message{body = Body}),
			mnesia:dirty_delete_object(offline_msg, OffMsg),
			mnesia:dirty_write(OffMsg#offline_msg{packet = Pkt2}); %% replace text of the origin message
		_ ->
			ok
	end,
	[Packet, Action];
offline_packet(#fasten_apply_to{id = _RetractId, sub_els = [#retract_id{}]}, [_, _] = Acc) ->
	Acc;
offline_packet(#mam_result{}, [Packet, Action]) ->
	[xmpp:set_subtag(Packet, #offline{}), Action].
offline_packet(Acc) ->
	Acc.


get_offline_msgs(Pred) ->
	case mnesia:transaction(fun() ->
		qlc:e(qlc:q([R || R = #offline_msg{packet = Pkt} <- mnesia:table(offline_msg), Pred(Pkt)])) end) of
		{atomic, Pkts} -> Pkts;
		Err -> Err
	end.

tags_pred(Tags) ->
	fun(Pkt) ->
		DecodedPkt = xmpp:decode(Pkt),
		lists:foldl(
			fun(Tag, Acc) ->
				case xmpp:get_subtag(DecodedPkt, Tag) of
					Tag -> true;
					_ -> Acc
				end
			end, false, Tags)
	end.
get_offline_msgs_by_tags(Tags) ->
	get_offline_msgs(tags_pred(Tags)).
get_offline_msgs_by_tag(Tag) ->
	get_offline_msgs_by_tags([Tag]).

get_offline_pkts_by_tag(Tag) ->
	get_offline_pkts_by_tags([Tag]).
get_offline_pkts_by_tags(Tags) ->
	[xmpp:decode(Pkt) || #offline_msg{packet = Pkt} <- get_offline_msgs_by_tags(Tags)].

upd_offline_msgs(Pred, UpdFun) ->
	case mnesia:transaction(fun() ->
		qlc:e(qlc:q([UpdFun(R) || R = #offline_msg{packet = Pkt} <- mnesia:table(offline_msg), Pred(Pkt)])) end) of
		{atomic, Pkts} -> Pkts;
		Err -> Err
	end.

remove_offline_msgs_by_tags([]) -> [];
remove_offline_msgs_by_tags([_ | _] = Tags) ->
	upd_offline_msgs(tags_pred(Tags), fun mnesia:dirty_delete_object/1).

remove_all_private_msgs(#jid{} = RoomOrUser) ->
	BareJID = jid:remove_resource(RoomOrUser),
	PredFun =
		fun PredFun(#xmlel{name = <<"message">>} = Pkt) ->
				PredFun(#message{} = xmpp:decode(Pkt));
			PredFun(#message{type = chat, from = From, to = To}) ->
				jid:remove_resource(From) == BareJID orelse jid:remove_resource(To) == BareJID;
			PredFun(_) -> false
		end,
	upd_offline_msgs(PredFun, fun mnesia:dirty_delete_object/1).
