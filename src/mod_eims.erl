-module(mod_eims).
-compile(export_all).
-behaviour(gen_mod).

%% API
-export([]).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include_lib("eims_api_codec.hrl").
-include("translate.hrl").
-include("mod_muc_room.hrl").
-include("mod_mam.hrl").
-include("eims.hrl").

-record(eims_ws, {pid :: undefined | pid(), jid :: undefined | #jid{}, channels = [] :: list(binary())}).

-import(eims_api_codec, [packet_error/1, packet_result/1, packet_result/2]).

start(Host, _Opts) ->
%%	ejabberd_mnesia:create(?MODULE, eims_ws,
%%		[{ram_copies, [node()]},
%%			{index, [jid]},
%%			{attributes, record_info(fields, eims_ws)}]),
	ejabberd_hooks:add(sm_remove_connection_hook, Host, ?MODULE, user_offline, 130),
	ejabberd_hooks:add(filter_packet, fun ?MODULE:filter_packet/1, 125).

stop(Host) ->
	ejabberd_hooks:delete(sm_remove_connection_hook, Host, ?MODULE, user_offline, 130),
	ejabberd_hooks:delete(filter_packet, fun ?MODULE:filter_packet/1, 125).

mod_opt_type(testnet) ->
	econf:bool();
mod_opt_type(_) -> [testnet].
mod_options(_Host) ->
	[{testnet, true}].

mod_doc() ->
	#{desc => ?T("mod_eims params"), opts =>
	[{testnet,
		#{value => ?T("testnet"),
			desc => ?T("Indicates whether the API in use is actually the test API. false for production server, true for test server.")}}]}.

depends(_Host, _Opts) ->
	[].

%% ejabberd hooks
user_offline(_SID, #jid{luser = User, lserver = Host} = JID, _Info) ->
	case ejabberd_sm:get_user_resources(User, Host) of
		[] -> [Pid ! {tcp_closed, []} || #eims_ws{pid = Pid} <- get_client_pids(JID)];
		_ -> ok
	end.

filter_packet(#message{type = chat, from = #jid{luser = <<"rfq.", _/binary>> = Room, lserver = Server}, to = To, meta = #{bot := _} = Meta} = Pkt) ->
	MucHost = ?MUC_HOST,
	[send_packet(Pid, Pkt, case {Meta, Server} of
		                     {#{from := {Pid, To, WsPkt}}, MucHost} -> WsPkt;
		                     {#{from := {_, To, WsPkt}}, MucHost} -> WsPkt#packet{id = 0};
		                     {_, MucHost} -> #packet{usIn = erlang:system_time(microsecond)};
							 _ -> ok
	                     end) || #eims_ws{pid = Pid, jid = J, channels = Channels} <- get_client_pids(To),
												J == jid:remove_resource(To), lists:member(Room, Channels)],
	Pkt;
filter_packet(Pkt) ->
	Pkt.

%%===============================================================
%% API
%%===============================================================
send_packet(_Pid, _Pkt, ok) -> ok; %%TODO refactor send_packet
%%send_packet(Pid, #message{from = #jid{luser = Room}, body = [], meta = #{bot := retract}} = Pkt, WsPkt) -> %% TODO packet for retract
%%	#fasten_apply_to{id = Id} = xmpp:get_subtag(Pkt, #fasten_apply_to{}),
%%	Pid ! {send, (packet_result(WsPkt))#packet_result{result = #{<<"channel">> => Room, <<"remove">> => Id}}};
send_packet(Pid, #message{from = #jid{luser = Room}, body = [#text{data = <<"ERROR: ", Reason/binary>>}], meta = #{bot := error}}, WsPkt) ->
	ResPkt = (packet_error(WsPkt))#packet_error{
		code = 13008,
		message = <<"request_failed">>,
		data = #{<<"reason">> => Reason, <<"channel">> => Room}},
	Pid ! {send, ResPkt};
send_packet(Pid, #message{from = #jid{luser = Room}, body = [#text{data = Text}], meta = #{bot := message, command := Name}}, WsPkt) ->
	Pid ! {send, packet_result(WsPkt, #{<<"channel">> => Room, <<"message">> => Text, <<"method">> => Name})};
send_packet(Pid, #message{from = #jid{luser = Room}, body = [#text{data = Text}], meta = #{bot := payload, command := Name}} = Pkt, WsPkt) ->
	Map = eims:get_json_payload(Pkt),
	Pid ! {send, packet_result(WsPkt, #{<<"channel">> => Room, <<"data">> => Map, <<"method">> => Name})};
%%	Pid ! {send, packet_result(WsPkt, #{<<"channel">> => Room, <<"data">> => Map, <<"message">> => Text, <<"command">> => Name})}; %% add message for test
send_packet(_Pid, _Pkt, _WsPkt) -> ok.

%%=================================================
%% Table API
%%=================================================
get_client_pids(#jid{} = JID) ->
	mnesia:dirty_index_read(eims_ws, jid:remove_resource(JID), #eims_ws.jid).

get_client_by_pid(Pid) ->
	case mnesia:dirty_read(eims_ws, Pid) of
		[#jid{} = JID] -> {ok, JID};
		[] -> ?err("User not found by pid ~p" , [Pid]),
			{error, not_found}
	end.

remove_client_pid() ->
	remove_client_pid(self()).
remove_client_pid(Pid) ->
	mnesia:dirty_delete(eims_ws, Pid).

add_client_pid(#jid{} = JID) ->
	add_client_pid(JID, self()).
add_client_pid(#jid{} = JID, Pid) ->
	add_client_pid(JID, Pid, []).
add_client_pid(#jid{} = JID, Pid, Channels) ->
	mnesia:dirty_write(#eims_ws{pid = Pid, jid = jid:remove_resource(JID), channels = Channels}).