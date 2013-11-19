%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2013, Bip Thelin
%%%
%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%%%
%%% @doc Pure Erlang implementation of the SipHash-2-4 PRF
%%%
%%%      SipHash is a secure cryptographic algorithm optimized for speed
%%%      and short messages. Especially suitable for Hash Tables, etc.
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(siphash).

%%%_* Exports ==========================================================
-export([hash/2]).

-export_type([message/0]).
-export_type([hash/0]).
-export_type([key/0]).

%%%_* Macros ===========================================================
-record(state, {v0, v1, v2, v3}).

% Number of compression rounds
-define(c, 2).

% Number of finalization rounds
-define(d, 4).

%%%_* Code =============================================================
%%%_ * Types -----------------------------------------------------------
-type message() :: integer() | list() | binary().
-type key()     :: integer() | list() | binary().
-type hash()    :: integer().

%%%_ * API -------------------------------------------------------------
-spec hash(message(), key())        -> hash().
hash(Msg, Key) when is_integer(Key) -> hash(Msg, integer_to_binary(Key));
hash(Msg, Key) when is_list(Key)    -> hash(Msg, list_to_binary(Key));
hash(Msg, Key) when is_binary(Key)  -> finalize(compress(pad(Msg), init(Key)));
hash(_, _)                          -> throw(illegal_key).

%%%_* Private functions ================================================
% 1.
%% Initialization
%% Four 64-bit words of internal state v0; v1; v2; v3 are initialized
init(<<K0b:8/binary, K1b:8/binary>>) ->
    K0 = binary:decode_unsigned(K0b, little),
    K1 = binary:decode_unsigned(K1b, little),
    #state{ v0 = K0 bxor 16#736f6d6570736575
          , v1 = K1 bxor 16#646f72616e646f6d
          , v2 = K0 bxor 16#6c7967656e657261
          , v3 = K1 bxor 16#7465646279746573 }.

% 2.
%% Compression
compress(<<>>, State)                     -> State;
compress(<<X:64/little, Res/binary>>, S0) ->
    S1 = lists:foldl( fun(_, S) -> sipround(S) end
                    , sipround(S0#state{v3 = S0#state.v3 bxor X})
                    , lists:seq(1, ?c - 1)),
    compress(Res, S1#state{v0 = S1#state.v0 bxor X}).

% 3.
%% Finalization
finalize(#state{v2 = V2} = S0) ->
    S1 = lists:foldl( fun(_, S) -> sipround(S) end
                    , sipround(S0#state{v2 = V2 bxor 16#FF})
                    , lists:seq(1, ?d - 1)),
    S1#state.v0 bxor S1#state.v1 bxor S1#state.v2 bxor S1#state.v3.

pad(Msg) when is_integer(Msg) -> pad(integer_to_binary(Msg));
pad(Msg) when is_list(Msg)    -> pad(list_to_binary(Msg));
pad(Msg) when is_binary(Msg)  ->
    Len = byte_size(Msg),
    <<Msg/binary, 0:((7 - Len rem 8) * 8), Len:8>>.

sipround(#state{v0 = V0, v1 = V1, v2 = V2, v3 = V3}) ->
    Rv0  = mask(V0 + V1),
    Rv1  = Rv0 bxor rotl(V1, 13),
    Rv2  = mask(V2 + V3),
    Rv3  = Rv2 bxor rotl(V3, 16),
    Rv01 = mask(rotl(Rv0, 32) + Rv3),
    Rv21 = mask(Rv1 + Rv2),
    #state{ v0 = Rv01
          , v1 = rotl(Rv1, 17) bxor Rv21
          , v2 = rotl(Rv21, 32)
          , v3 = Rv01 bxor rotl(Rv3, 21) }.

mask(X)    -> X band 16#FFFFFFFFFFFFFFFF.
rotl(V, R) -> mask((V bsl R)) bor (V bsr (64 - R)).

%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%%%
%%  Test vectors from the reference implementation.
%%
%%  SipHash-2-4 output with
%%     k = 00 01 02 ...
%%     and
%%     in = (empty string)
%%     in = 00 (1 byte)
%%     in = 00 01 (2 bytes)
%%     in = 00 01 02 (3 bytes)
%%     ...
%%     in = 00 01 02 ... 3e (63 bytes)
hash_32_test() ->
    Key     = << 16#00, 16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07
               , 16#08, 16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f >>,
    Vectors =
        [ 16#726fdb47dd0e0e31, 16#74f839c593dc67fd, 16#0d6c8009d9a94f5a
        , 16#85676696d7fb7e2d, 16#cf2794e0277187b7, 16#18765564cd99a68d
        , 16#cbc9466e58fee3ce, 16#ab0200f58b01d137, 16#93f5f5799a932462
        , 16#9e0082df0ba9e4b0, 16#7a5dbbc594ddb9f3, 16#f4b32f46226bada7
        , 16#751e8fbc860ee5fb, 16#14ea5627c0843d90, 16#f723ca908e7af2ee
        , 16#a129ca6149be45e5, 16#3f2acc7f57c29bdb, 16#699ae9f52cbe4794
        , 16#4bc1b3f0968dd39c, 16#bb6dc91da77961bd, 16#bed65cf21aa2ee98
        , 16#d0f2cbb02e3b67c7, 16#93536795e3a33e88, 16#a80c038ccd5ccec8
        , 16#b8ad50c6f649af94, 16#bce192de8a85b8ea, 16#17d835b85bbb15f3
        , 16#2f2e6163076bcfad, 16#de4daaaca71dc9a5, 16#a6a2506687956571
        , 16#ad87a3535c49ef28, 16#32d892fad841c342, 16#7127512f72f27cce
        , 16#a7f32346f95978e3, 16#12e0b01abb051238, 16#15e034d40fa197ae
        , 16#314dffbe0815a3b4, 16#027990f029623981, 16#cadcd4e59ef40c4d
        , 16#9abfd8766a33735c, 16#0e3ea96b5304a7d0, 16#ad0c42d6fc585992
        , 16#187306c89bc215a9, 16#d4a60abcf3792b95, 16#f935451de4f21df2
        , 16#a9538f0419755787, 16#db9acddff56ca510, 16#d06c98cd5c0975eb
        , 16#e612a3cb9ecba951, 16#c766e62cfcadaf96, 16#ee64435a9752fe72
        , 16#a192d576b245165a, 16#0a8787bf8ecb74b2, 16#81b3e73d20b49b6f
        , 16#7fa8220ba3b2ecea, 16#245731c13ca42499, 16#b78dbfaf3a8d83bd
        , 16#ea1ad565322a1a0b, 16#60e61c23a3795013, 16#6606d7e446282b93
        , 16#6ca4ecb15c5f91e1, 16#9f626da15c9625f3, 16#e51b38608ef25f57
        , 16#958a324ceb064572
        ],

        lists:foldl(
            fun(I, M) ->
                ?assertEqual(lists:nth(I, Vectors), hash(M, Key)),
                <<M/binary, (I-1)/integer>>
            end
          , <<>>
          , lists:seq(1, 64)).

-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 4
%%% End:
