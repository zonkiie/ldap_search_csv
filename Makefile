CC := gcc
CFLAGS := -g 
#-DLDAP_DEPRECATED
LDFLAGS := 
LDLIBS := -lldap -llber
PROGS := ldap_search_1
C_SOURCE_FILES := $(*.c)
OBJECT_FILES := $(C_SOURCE_FILES:.c=.o)

all: $(OBJECT_FILES) $(PROGS)
ldap_search_1: ldap_search_1.o
clean:
	-rm -rf *.o $(PROGS)

