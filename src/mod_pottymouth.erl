-module(mod_pottymouth).

-behaviour(gen_mod).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").

-export([
  start/2,
  stop/1,
  user_send_packet/1,
  mod_opt_type/1,
  mod_doc/0,
  depends/2,
  reload/3,
  mod_options/1,
  getMessageLang/1,
  filterMessageText/2
]).

-import(banword_gen_server, [start/0, stop/0, member/1]).
-import(nomalize_leet_gen_server, [normalize/1]).

getMessageLang(Msg) ->
  LangAttr = xmpp:get_lang(Msg),
  if
    (LangAttr /= <<>>) ->
      Lang = list_to_atom(binary_to_list(LangAttr));
    true ->
      Lang = default
  end,
  Lang.

censorWord({Lang, Word} = _MessageTerm) ->
  % we need unicode characters to normlize the word
  NormalizedWord = normalize_leet_gen_server:normalize({Lang, unicode:characters_to_list(list_to_binary(Word))}),
  % we need bytewise format for banword lookup
  IsBadWord = banword_gen_server:member({Lang, binary_to_list(unicode:characters_to_binary(NormalizedWord))}),
  if
    IsBadWord ->
      "****";
    true ->
      Word
  end.

filterWords(L) ->
  lists:map(fun censorWord/1, L).

filterMessageText(Lang, MessageText) ->
  try filterMessageText2(Lang, MessageText) of
    R ->
      R
  catch exit:{noproc, {gen_server, call, [_, _]}} ->
    ?DEBUG("Blacklist of language '~p' not found, using 'default' list.", [Lang]),
    filterMessageText2(default, MessageText)
  end.

filterMessageText2(Lang, MessageText) ->
  % we want to token-ize utf8 'words'
  MessageWords = string:lexemes(unicode:characters_to_list(MessageText, utf8), " "),
  MessageTerms = [{Lang, Word} || Word <- MessageWords],
  % we get back bytewise format terms (rather than utf8)
  string:join(filterWords(MessageTerms), " ").

start(Host, Opts) ->
  Args = get_opts(Host, Opts),
  [supervisor:start_child(ejabberd_gen_mod_sup, #{id => Module:serverName(Lang),
    start => {Module, start, [Arg]},
    restart => transient,
    shutdown => 2000,
    type => worker,
    modules => [Module]}) || {Module, BlCms} <- Args, {Lang, _} = Arg <- BlCms],
  ejabberd_hooks:add(user_send_packet, Host, ?MODULE, user_send_packet, 89),
  ok.

stop(Host) ->
  Args = get_opts(Host),
  [begin Module:stop(Arg), supervisor:delete_child(ejabberd_gen_mod_sup, Module:serverName(Lang)) end
    || {Module, BlCms} <- Args, {Lang, _} = Arg <- BlCms],
  ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, user_send_packet, 89),
  ok.

get_opts(Host) ->
  get_opts(Host, gen_mod:get_module_opts(Host, mod_pottymouth)).
get_opts(_Host, Opts) ->
  [{M, gen_mod:get_opt(Opt, Opts)} ||
    {M, Opt} <- [{banword_gen_server, blacklists}, {normalize_leet_gen_server, charmaps}]].

mod_opt_type(blacklists) -> fun(A) when is_list(A) -> A end;
mod_opt_type(charmaps) -> fun(A) when is_list(A) -> A end;
mod_opt_type(check_fun) -> fun(A) when is_atom(A) -> A end;
mod_opt_type(_) -> [check_fun, blacklists, charmaps].
depends(_Host, _Opts) -> [].
reload(_Host, _NewOpts, _OldOpts) -> ok.
mod_options(_) ->
  [{blacklists, []}, {charmaps, []}, {check_fun, check_banword}].
mod_doc() -> #{}.

user_send_packet({#message{type = groupchat, from = #jid{lresource = Resource},
                           body = [#text{data = <<_/integer, _/binary>> = BodyText} = Text]} = Pkt, C2SState}) ->
  Lang = getMessageLang(Pkt),
  FilteredMessageWords = binary:list_to_bin(filterMessageText(Lang, binary:bin_to_list(BodyText))),
  case {FilteredMessageWords, Resource} of
    {BodyText, _} -> ok;
    {_, <<"converse.js", _/binary>>} -> %% only for converse.js client
      Packet =
        case xmpp:get_subtag(Pkt, #replace{}) of
          #replace{id = ReplacedId} ->
            xmpp:set_subtag(xmpp:remove_subtag(Pkt, #replace{}), #origin_id{id = ReplacedId});
          _ -> Pkt
        end,
      eims:send_edit(Packet, FilteredMessageWords);
    _ -> ok
  end,
  {Pkt#message{body = [Text#text{data = FilteredMessageWords}]}, C2SState};
user_send_packet(Packet) ->
  Packet.