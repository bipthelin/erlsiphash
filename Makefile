PROJECT = siphash

include erlang.mk

test: tests
	erl -noshell -pa ebin -eval 'eunit:test("ebin", [verbose])' -s init stop
