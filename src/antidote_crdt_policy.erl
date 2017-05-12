%% -------------------------------------------------------------------
%%
%% riak_dt_policy: A DVVSet based access control policy data type
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

%% @doc
%% A data type for access control policies.
%% Read returns the minimum of the concurrently added rights
%%
%% This is implemented, by assigning a unique token to every assign operation.
%% The downstream effect carries the tokens of overridden values, so that
%% only assignments, which happened before are really overridden and
%% concurrent assignments are maintained
%%
%% The implementation is an adaptation of the multi-value register implementation
%%
%% @end

-module(antidote_crdt_policy).

-behaviour(antidote_crdt).

%% Callbacks
-export([ new/0,
          value/1,
          downstream/2,
          update/2,
          equal/2,
          to_binary/1,
          from_binary/1,
          is_operation/1,
          require_state_downstream/1,
          is_bottom/1
        ]).


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export_type([policy/0, policy_op/0]).

%% TODO: make opaque
-type policy() :: [{term(), uniqueToken()}].
-type uniqueToken() :: term().
-type policy_effect() ::
    {Value::term(), uniqueToken(), Overridden::[uniqueToken()]}
  | {reset, Overridden::[uniqueToken()]}.


-type policy_op() :: {assign, term()}.


%% @doc Create a new, empty `policy()'
-spec new() -> policy().
new() ->
    [].



%% @doc The values of this `policy()'. Returns the minimum of all concurrently
%% assigned rights
-spec value(policy()) -> [term()].
value(Policy) ->
    case [V || {V, _} <- Policy] of
      [] ->
        [];
      [Head|Tail] ->
        lists:foldl(fun ordsets:intersection/2, Head, Tail)
    end.


-spec downstream(policy_op(), policy()) -> {ok, policy_effect()}.
downstream({assign, Value}, Policy) ->
    Token = unique(),
    Overridden = [Tok || {_, Tok} <- Policy],
    {ok, {Value, Token, Overridden}};
downstream({reset, {}}, Policy) ->
  Overridden = [Tok || {_, Tok} <- Policy],
  {ok, {reset, Overridden}}.

-spec unique() -> uniqueToken().
unique() ->
    crypto:strong_rand_bytes(20).


-spec update(policy_effect(), policy()) -> {ok, policy()}.
update({Value, Token, Overridden}, Policy) ->
    % remove overridden values
    Policy2 = [{V, T} || {V, T} <- Policy, not lists:member(T, Overridden)],
    % insert new value
    {ok, insert_sorted({Value, Token}, Policy2)};
update({reset, Overridden}, Policy) ->
  Policy2 = [{V, T} || {V, T} <- Policy, not lists:member(T, Overridden)],
  {ok, Policy2}.

% insert value into sorted list
insert_sorted(A, []) -> [A];
insert_sorted(A, [X|Xs]) when A < X -> [A, X|Xs];
insert_sorted(A, [X|Xs]) -> [X|insert_sorted(A, Xs)].


-spec equal(policy(), policy()) -> boolean().
equal(Policy1, Policy2) ->
    Policy1 == Policy2.

-define(TAG, 99).
-define(V1_VERS, 1).

-spec to_binary(policy()) -> binary().
to_binary(Policy) ->
    <<?TAG:8/integer, ?V1_VERS:8/integer, (term_to_binary(Policy))/binary>>.

%% @doc Decode binary `mvreg()'
-spec from_binary(binary()) -> {ok, policy()} | {error, term()}.
from_binary(<<?TAG:8/integer, ?V1_VERS:8/integer, Bin/binary>>) ->
    {ok, riak_dt:from_binary(Bin)}.


%% @doc The following operation verifies
%%      that Operation is supported by this particular CRDT.
-spec is_operation(term()) -> boolean().
is_operation({assign, _}) -> true;
is_operation({reset, {}}) -> true;
is_operation(_) -> false.

require_state_downstream(_) ->
     true.

is_bottom(State) -> State == new().


%% ===================================================================
%% Private API
%% ===================================================================
%% following code was created by mweber on github :
%% https://github.com/mweberUKL/antidote/blob/acgregate_integration/src/crdt_policy.erl
%% sets rights changing

% % Private
% %-spec add_right(right(), binary(), policy()) -> {ok, policy()}.
% add_right(Right, Token, Policy) ->
%     case orddict:find(Right, Policy) of
%         {ok, Tokens} ->
%             case lists:member(Token, Tokens) of
%                 true ->
%                     {ok, Policy};
%                 false ->
%                     {ok, orddict:store(Right, Tokens++[Token], Policy)}
%             end;
%         error ->
%             {ok, orddict:store(Right, [Token], Policy)}
%     end.

% %-spec remove_right(right(), [binary()], policy()) -> policy().
% remove_right(Right, RemoveTokens, Policy) ->
%     case orddict:find(Right, Policy) of
%         {ok, Tokens} ->
%             RestTokens = Tokens--RemoveTokens,
%             case RestTokens of
%                 [] ->
%                     orddict:erase(Right, Policy);
%                 _ ->
%                     orddict:store(Right, RestTokens, Policy)
%             end;
%         error ->
%             Policy % if the right is not in the policy anymore, it was already removed by a different policy change
%     end.

% %-spec remove_rights(orddict:orddict(), policy()) -> policy().
% remove_rights(Orddict, Policy) ->
%     orddict:fold(fun(Right, Tokens, Res) ->
%                    remove_right(Right, Tokens, Res)
%                  end, Policy, Orddict).

% %-spec unique(actor()) -> binary().
% unique(_Actor) ->
% crypto:strong_rand_bytes(20).

%% ===================================================================
%% EUnit tests
%% ===================================================================
-ifdef(TEST).

upd(Update, State) ->
    {ok, Downstream} = downstream(Update, State),
    {ok, Res} = update(Downstream, State),
    Res.

reset_test() ->
    R1 = new(),
    ?assertEqual([], value(R1)),
    ?assertEqual(true, is_bottom(R1)),
    R2 = upd({assign, ordsets:from_list([read])}, R1),
    ?assertEqual(ordsets:from_list([read]), value(R2)),
    ?assertEqual(false, is_bottom(R2)),
    R3 = upd({reset, {}}, R2),
    ?assertEqual([], value(R3)),
    ?assertEqual(true, is_bottom(R3)).

  minimum_test() ->
      Policy1 = new(),
      %% Create policy with overlapping rights
      {ok, Op1} = downstream({assign, ordsets:from_list([read, write])}, Policy1),
      {ok, Policy2} = update(Op1, Policy1),
      {ok, Op2} = downstream({assign, ordsets:from_list([write, own])}, Policy1),
      {ok, PolicyMult} = update(Op2, Policy2),

      %% The minimum should be the intersection of the sets
      ?assertEqual([write], value(PolicyMult)).

-endif.
