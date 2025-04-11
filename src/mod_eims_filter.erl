%%%-------------------------------------------------------------------
%%% @doc
%%% module for filtering messages
%%% @end
%%%-------------------------------------------------------------------
-module(mod_eims_filter).
-compile(export_all).

-behaviour(gen_mod).

-export([start/2, stop/1, depends/2, mod_options/1, mod_opt_type/1, filter_packet_fun/3, mod_doc/0]).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include("translate.hrl").
-include("eims.hrl").

mod_options(_Host) ->
    [{except_from, []},
        {filter_regex, []},
        {except_replace, []}].

mod_opt_type(except_from) ->
    econf:list(econf:binary());
mod_opt_type(filter_regex) ->
    econf:list(econf:binary());
mod_opt_type(except_replace) ->
    econf:list(econf:binary()).

depends(_Host, _Opts) ->
    [].

%%except_from() ->
%%    [].

mod_doc() ->
    #{desc =>
    ?T("filtering messages for EIMS"),
        opts =>
        [
            {except_from,
            #{value => ?T("ListOfAdminUsers"),
                desc =>
                ?T("Messages are not filtered for those users (admins, CM, moderators)")}},
            {filter_regex,
                #{value => ?T("RegExList"),
                    desc =>
                    ?T("List of regular expressions which are wipe out from messages, like links etc")}}
        ]}.

start(_Host, Opts) ->
    ExceptFrom = gen_mod:get_opt(except_from, Opts),
    FilterRegex = [begin
                       {ok, Y} = re:compile(X,[caseless]),
                       Y
                   end || X <- gen_mod:get_opt(filter_regex, Opts)],
    ExceptReplace = gen_mod:get_opt(except_replace, Opts),
    FilterFun = filter_packet_fun(ExceptFrom, FilterRegex, ExceptReplace),
    ejabberd_config:set_option(eims_filter_fun, FilterFun),
    ejabberd_hooks:add(filter_packet, FilterFun, 121).

stop(_Host) ->
    FilterFun = ejabberd_config:get_option(eims_filter_fun, undefined),
    case FilterFun of
        undefined ->
             ok;
        _ ->
            ejabberd_hooks:delete(filter_packet, FilterFun, 121)
    end.

filter_packet_fun(ExceptFrom, FilterRegex, ExceptReplace) ->
    fun
        (Packet) ->
            filter_packet(ExceptFrom, FilterRegex, ExceptReplace,Packet)
    end.

%% Return drop to drop the packet, or the original input to let it through.
%% From and To are jid records.
filter_packet(ExceptFrom, FilterRegex, ExceptReplace, #message{from = From} = Packet) ->
    NewPacket1 = filter_packet(ExceptFrom, FilterRegex, ExceptReplace, From, Packet),
    NewPacket2 = message_append_real_jid(NewPacket1),
    NewPacket2;
filter_packet(_ExceptFrom, _FilterRegex, ExceptReplace, #presence{ from = #jid{user = <<"whale.", _/binary >> = User, server = Server}
    , to = #jid{server = <<"conference.",_/binary>>, resource = RequestedNick} = To} = Packet) ->
    %% for "whales", we not allow to set nick in the MUC rooms other than received from EIMS
    case mod_private:get_data(User, Server) of
        [#xmlel{name = <<"eims">>
            , children = [
                #xmlel{name = <<" ">>
                    , children= [{xmlcdata, Nickname}]} | _]}] ->
            case Nickname == RequestedNick of
                false ->
                    Packet#presence{to = To#jid{resource = Nickname, lresource = Nickname}};
                _ ->
                    Packet
            end;
        _Data ->
            case RequestedNick of
                <<"whale.", _/binary >> ->
                    Packet;
                _ ->
                    Packet#presence{to = To#jid{resource = <<"whale.", RequestedNick/binary>>, lresource = <<"whale.", RequestedNick/binary>>}}
            end
    end;
filter_packet(_ExceptFrom, _FilterRegex, ExceptReplace, Packet) ->
    Packet.

filter_packet(ExceptFrom, FilterRegex, ExceptReplace, #jid{luser = <<"whale.", _/binary>> = User} = From,
    #message{subject = Subject, body = Body, sub_els = SebEls, id = Id, to = #jid{luser = Room, lserver = RoomHost}} = Packet) ->
    case lists:member(User, ExceptFrom) of
        true ->
            Packet;
        _ ->
            Subject1 = filter_list(FilterRegex, ExceptReplace, Subject),
            Body1 = filter_list(FilterRegex, ExceptReplace, Body),
            Packet#message{subject = Subject1, body = Body1}
    end;
filter_packet(_ExceptFrom, _FilterRegex, _ExceptReplace, _From, Packet) -> Packet.

filter_list(FilterRegex, ExceptReplace, [H | T]) ->
    [filter_text(FilterRegex, ExceptReplace, H) | filter_list(FilterRegex, ExceptReplace, T)];
filter_list(_, _ExceptReplace, []) ->
    [];
filter_list(_, _ExceptReplace, V) ->
    V.

filter_text(FilterRegex, ExceptReplace, #text{data = D} = T) ->
    T#text{data = filter_string(FilterRegex, ExceptReplace, D)};
filter_text(_, _ExceptReplace, T) ->
    T.

filter_string(FilterRegex, ExceptReplace, String) ->
    ExceptReplace2 =
        lists:flatten(
            [case re:run(String, <<"(", Re/binary, ")">>, [global, {capture,[1], binary}]) of
                 {match, Captured} -> Captured;
                 nomatch -> []
             end || Re <- ExceptReplace]),
    DummyReplace = lists:zip(ExceptReplace2,
        [<<"$#!", (integer_to_binary(I))/binary>> || I <- lists:seq(1, length(ExceptReplace2))]),
    String2 = lists:foldl(fun replace_word/2, String,
        DummyReplace ++ [{<<DummyWord/binary, "@">>, <<"http://dummy.com">>} || {_, DummyWord} <- DummyReplace]), %% insert dummy link to replace on next row
    String3 = lists:foldl(fun filter_out_word/2, String2, FilterRegex),
    lists:foldl(fun replace_word/2, String3, [{DummyWord, Replace} || {Replace, DummyWord} <- DummyReplace]).

filter_out_word(Re, String) ->
    NewString = erlang:iolist_to_binary(
        re:replace(String, Re, <<"[bot removed link]">>, [global])),
    NewString.

replace_word({ExcReplace, ReplaceWord}, String) ->
    erlang:iolist_to_binary(string:replace(String, ExcReplace, ReplaceWord, all)).

address_replace_or_add([], RealAddress, {Els, false}) ->
    [RealAddress | Els];
address_replace_or_add(T, _, {Els, true}) ->
    Els ++ T;
address_replace_or_add([#xmlel{attrs = Attrs} = Address | T], RealAddress, {Els, false}) ->
    {NewAddress, Stop} = case lists:member({<<"type">>, <<"ofrom">>}, Attrs) of
                             true ->
                                 {RealAddress, true};
                             false ->
                                 {Address, false}
                 end,
    address_replace_or_add(T, RealAddress, {[NewAddress | Els], Stop}).

addresses_add_real_jid([], RealAddress, {Els, false}) ->
    X = #xmlel{name = <<"addresses">>,
        attrs = [{<<"xmlns">>,<<"http://jabber.org/protocol/address">>}],
        children = [RealAddress]},
    [X | Els];
addresses_add_real_jid(T, _, {Els, true}) ->
    Els ++ T;
addresses_add_real_jid([#xmlel{name = <<"addresses">>, children = AddressList} = Addresses| T], RealAddress, {Els, false}) ->
    NewAddresses = Addresses#xmlel{children = address_replace_or_add(AddressList, RealAddress, {[], false})},
    addresses_add_real_jid(T, RealAddress, {[NewAddresses | Els], true});
addresses_add_real_jid([H | T], RealAddress, {Els, false}) ->
    addresses_add_real_jid(T, RealAddress, {[H | Els], false}).

message_append_real_jid(#message{from = #jid{user = <<"whale.", _/binary >> = User, server = Server},
    to = #jid{server = <<"conference.",_/binary>>}, sub_els = Els} = Packet) ->
    Jid = jid:make(User, Server),
    RealAddress = #xmlel{name = <<"address">>, attrs = [{<<"type">>, <<"ofrom">>}, {<<"jid">>, jid:encode(Jid)}]},
    Packet#message{sub_els = addresses_add_real_jid(Els, RealAddress,{[], false})};
message_append_real_jid(P) ->
    P.