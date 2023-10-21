CC = gcc
CFLAGS = -g -O2 -fPIC -I./
LIBS = $(shell pkg-config --cflags --libs libsodium x264 opus vpx libavcodec libavutil)

tox_client_killer: tox_client_killer.o toxcore_amalgamation.a
	$(CC) $(CFLAGS) tox_client_killer.o toxcore_amalgamation.a $(LIBS) -o tox_client_killer

tox_client_killer.o: tox_client_killer.c
	$(CC) -c $(CFLAGS) $(LIBS) $< -o $@

toxcore_amalgamation.a: toxcore_amalgamation.o
	ar rcs toxcore_amalgamation.a toxcore_amalgamation.o

toxcore_amalgamation.o: toxcore_amalgamation.c
	$(CC) -c $(CFLAGS) $(LIBS) $< -o $@


clean:
	rm -f tox_client_killer tox_client_killer.o toxcore_amalgamation.o toxcore_amalgamation.a

