RESULT = dct

INCLUDES = parse.h display.h cmd.h dissect.h control.h
INCLUDES_DIR = includes/

INCLUDES_PRE = $(addprefix $(INCLUDES_DIR),$(INCLUDES))

SOURCES = main.c parse.c display.c ../filter.c cmd.c dissect.c control.c

$(RESULT) : $(SOURCES) $(INCLUDES_PRE)
	gcc -I ../includes $(SOURCES) -o $(RESULT)

.PHONY: clean
clean :
	rm $(RESULT)
