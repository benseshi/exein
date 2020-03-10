CC=gcc
NAME=training-forwarder

$(NAME): nlf.c
	$(CC) -o $@ $^

.PHONY: clean

clean:
	$(RM) -f $(NAME)
