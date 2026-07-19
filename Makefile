NAME = main

CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -flto -O0

SRC_DIR = src/
INCLUDES = include/
OBJ_DIR = obj/


SRC = $(wildcard $(SRC_DIR)*.c)
SRC = $(shell find $(SRC_DIR) -type f -name "*.c")

OBJ = $(SRC:.c=.o)
OBJ := $(patsubst $(SRC_DIR)%,$(OBJ_DIR)%, $(OBJ))

BBLK = \e[1;30m
BRED = \e[1;31m
BGRN = \e[1;92m
BYEL = \e[1;33m
BBLU = \e[1;34m
BMAG = \e[1;35m
BCYN = \e[1;36m
BWHT = \e[1;37m
CRESET = \e[0m

all: $(NAME)

setcap:
	@echo "$(BMAG)Setting cap_net_bind_service$(NAME)$(CRESET)"
	@sudo setcap 'cap_net_bind_service=+ep' $(NAME)

$(NAME): $(OBJ) 
	@printf "\r\e[K"
	@echo "$(BBLU)Compiling $(NAME)$(CRESET)"
	@$(CC) -I$(INCLUDES) $(OBJ) $(CFLAGS) -o $(NAME)
	@echo "$(BBLU)$(NAME) compiled!$(CRESET)"
	
$(OBJ_DIR)%.o: $(SRC_DIR)%.c
	@printf "\r\e[K$(BGRN)Compiling: %s$(CRESET)" "$<"
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(dir $@)
	@${CC} $(CFLAGS) -c $< -o $@ -I$(INCLUDES)

clean:
	@rm -rf $(OBJ_DIR)
	@echo "$(BRED)object files cleaned!$(CRESET)"

fclean: clean
	@rm -f $(NAME)
	@echo "$(BRED)$(NAME) cleaned!$(CRESET)"
	@echo ""

re: fclean all

run r: all
	@echo "$(BGRN)Running $(NAME)$(CRESET)"
	./$(NAME)
	@echo "$(BGRN)$(NAME) done!$(CRESET)"

rerun: re run

.PHONY : all clean fclean re run