%%%----------------------------------------------------------------------
%%%
%%% ejabberd, Copyright (C) 2022-2025  IQOM R&D
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
%%%
%%%----------------------------------------------------------------------


-ifndef(EIMS_HRL).
-define(EIMS_HRL, true).

-include_lib("eims_xmpp.hrl").

-define(HOST, eims:host()).
-define(MUC_HOST, eims:muc_host()).
-define(REFRESH_TOKEN_INTERVAL, application:get_env(ejabberd, refresh_token_interval, 800)). %% in seconds
-define(ACCESS_TOKEN_INTERVAL, application:get_env(ejabberd, access_token_interval, 90)). %% in seconds

-define(err(Fmt), error_logger:error_msg(Fmt)).
-define(err(Fmt, Args), error_logger:error_msg(Fmt, Args)).

-define(dbg(Fmt, Args),
	case xmpp_config:debug(global) of
		{ok, true} -> error_logger:info_msg(Fmt, Args);
		_ -> false
	end).

%%-define(record_to_proplist(Def, Rec),
%%		lists:zip(record_info(fields, Def), tl(tuple_to_list(Rec)))).

-record(eims_auth, {access_token = [], refresh_token = [], time = eims:sys_time() :: integer()}).

%% Commands  
-define(help, <<"help">>).
-define(admin, <<"admin">>).
-define(member, <<"member">>).
-define(mute, <<"mute">>).
-define(kick, <<"kick">>).
-define(rban, <<"rban">>).
-define(runban, <<"runban">>).
-define(purge, <<"purge">>).
-define(stats, <<"stats">>).
-define(delmsg, <<"delmsg">>).
-define(ban, <<"ban">>).
-define(unban, <<"unban">>).
-define(banned, <<"banned">>).
-define(hserv_auth, <<"hserv_auth">>).
-define(user, <<"user">>).
-define(account, <<"account">>).
-define(edit, <<"edit">>).
-define(del, <<"del">>).
-define(badwords, <<"badwords">>).
-define(post, <<"post">>).
-define(muc, <<"muc">>).
-define(upd, <<"upd">>).
-define(file_rm, <<"file_rm">>).
-define(hserv_sub, <<"hserv_sub">>).

-record(eims_storage, {jid, nick = [], id = [], main_account_id = [], email = [], main_email = [],
							system_name = [], main_system_name = [], roles = [], access = allow, tstamp = 0}).
-record(eims_cmd, {cmd, out, broadcast = false, doc = [], acl = all, type = custom, stats = 0}).
-record(cmd, {name = <<>>, args = [], deep = 1, doc = <<>>, acl = [], default = [], args_format = #{plane => true},
				context, data = [], broadcast = false, custom = false, room_access = #{common => true}}).


-define(NS_TOKEN_TYPE, <<"ur:eims:token">>).

-define(UNAVAILABLE_MSG, <<"Integrated service is temporary unavaiable">>).
-define(AVAILABLE_MSG, <<"Integrated service is avaiable">>).


-define(UPD_TEXT(Cmd), <<" /", Cmd/binary, " command successfully updated">>).
-define(DEL_TEXT(Cmd), <<" /", Cmd/binary, " command successfully deleted">>).
-define(CUSTOM_UPD_TEXT(Cmd), <<" /", Cmd/binary, " command doc is succesfully updated">>).
-define(CUSTOM_DEFAULT_TEXT(Cmd), <<" /", Cmd/binary, " custom command doc text set to default">>).
-define(CUSTOM_INCLUDE_TEXT(Cmd), <<" /", Cmd/binary, " command cannot be updated. Custom command cannot include other custom command">>).
-define(CUSTOM_BASE_TEXT(Cmd), <<" /", Cmd/binary, " is base command and cannot be updated">>).


-endif.
