CC := gcc
CFLAGS := -g -std=c11 -D_GNU_SOURCE -D_XOPEN_SOURCE
#-DLDAP_DEPRECATED
LDFLAGS := 
LDLIBS := -lldap -llber -lsasl2 -ldl
PROGS := ldap_search_1 ldap_search_1_sync
C_SOURCE_FILES := $(*.c)
OBJECT_FILES := $(C_SOURCE_FILES:.c=.o)

all: $(OBJECT_FILES) $(PROGS)
ldap_search_1: ldap_search_1.o
ldap_search_1_sync: ldap_search_1_sync.o
clean:
	-rm -rf *.o $(PROGS)

install:
	install -m 0755 -o root -g root $(PROGS) /usr/local/bin/

uninstall:
	-rm -f /usr/local/bin/ldap_search_1

