NAME := main
CC := cc
CPPFLAGS += -Iinclude $(shell pkg-config --cflags ldns)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -MMD -MP
LDLIBS += $(shell pkg-config --libs ldns) -pthread
SRC := src/main.c src/handle_upstream_response.c \
       src/worker/handle_client_queries.c src/worker/parse_queries.c \
       src/worker/worker_loop.c src/worker/handle_timer.c \
       src/worker/handle_expired_context.c src/Hierarchical_Timing_Wheel/htw.c \
       src/utils/utils.c src/utils/id_pool.c src/utils/ctx_poll.c \
       src/utils/print.c src/logger/logger.c
OBJ := $(patsubst src/%.c,obj/%.o,$(SRC))

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LDLIBS) -o $@

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -r obj

fclean: clean
	$(RM) $(NAME)

re:
	$(MAKE) fclean
	$(MAKE) all

run r: all
	./$(NAME)

obj/test-timing-wheel: tests/timing_wheel.c src/Hierarchical_Timing_Wheel/htw.c include/timing_wheel.h
	@mkdir -p obj
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/timing_wheel.c src/Hierarchical_Timing_Wheel/htw.c -o $@

test: all obj/test-timing-wheel
	./obj/test-timing-wheel
	python3 tests/smoke.py

-include $(OBJ:.o=.d)
.PHONY: all clean fclean re run r test
