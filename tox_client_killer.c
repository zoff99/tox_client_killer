#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

// #include <tox/tox.h>
#include <tox.h>
#include <sodium.h>

static Tox *tox1 = NULL;
int online1 = 0;
int online2 = 0;
int added_friend = 0;
int stop_all = 0;
int count_sent = 0;
int count_rcv = 0;
int count_ack = 0;

static uint8_t *v = NULL;
static size_t v_size = 0;

void self_connection_status(Tox *tox, TOX_CONNECTION status, void *userData)
{
	if (status == TOX_CONNECTION_NONE) {
		printf("  DEBUG:Lost connection to the tox network tox=%p\n", tox);
	} else {
        online1 = 1;
        printf("  DEBUG:Connected to the tox network, status: %d #1\n", status);
	}
}

void friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data)
{
	TOX_ERR_FRIEND_ADD err;
	tox_friend_add_norequest(tox, public_key, &err);

	if (err != TOX_ERR_FRIEND_ADD_OK) {
		printf("  DEBUG:Could not add friend, error: %d\n", err);
	} else {
		printf("  DEBUG:Added to our friend list tox=%p\n", tox);
        added_friend = 1;
	}
}

void friend_connection_status(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status,
        void *user_data)
{
    printf("friend_connection_status tox=%p stats=%d\n", tox, connection_status);
    if (connection_status > 0)
    {
        online2 = 1;
    }
}

void friend_read_receipt(Tox *tox, uint32_t friend_number, uint32_t message_id, void *user_data)
{
    printf("  DEBUG:got receipt num=%d tox=%p\n", message_id, tox);
    count_ack++;
}

void sig_func(int sig)
{
    printf("  DEBUG:Caught signal: %d\n",sig);
    pthread_exit(0);
}

void get_my_toxid(Tox *tox, char *toxid_str)
{
    uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox, tox_id_bin);
    char tox_id_hex_local[TOX_ADDRESS_SIZE * 2 + 1];
    sodium_bin2hex(tox_id_hex_local, sizeof(tox_id_hex_local), tox_id_bin, sizeof(tox_id_bin));

    for (size_t i = 0; i < sizeof(tox_id_hex_local) - 1; i ++)
    {
        tox_id_hex_local[i] = toupper(tox_id_hex_local[i]);
    }

    snprintf(toxid_str, (size_t)(TOX_ADDRESS_SIZE * 2 + 1), "%s", (const char *)tox_id_hex_local);
}

void print_tox_id(Tox *tox)
{
    char tox_id_hex[TOX_ADDRESS_SIZE * 2 + 1];
    get_my_toxid(tox, tox_id_hex);
    printf("  DEBUG:--MyToxID--:%s\n", tox_id_hex);
}

void it(Tox *tox)
{
    for (int j=0;j<100;j++)
    {
        tox_iterate(tox, NULL);
        long long time = tox_iteration_interval(tox) * 1000000L;
        nanosleep((const struct timespec[]){{0, time}}, NULL);
    }
}

void c(size_t s)
{
    v = calloc(1, s);
    v_size = s;
}

void r()
{
    for (int i=0; i < v_size; i++)
    {
        v[i] = (rand() % 254) + 1;
    }
}

void ra()
{
    for (int i=0; i < v_size; i++)
    {
        v[i] = 'A' + random() % 26;
    }
}

void m3()
{
#define TOX_MSGV3_MSGID_LENGTH         32
#define TOX_MSGV3_TIMESTAMP_LENGTH     4
#define TOX_MSGV3_GUARD                2
    
    v[v_size - (TOX_MSGV3_GUARD + TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH)] = 0;
    v[v_size - (TOX_MSGV3_GUARD + TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH) + 1] = 0;
    int start = v_size - (TOX_MSGV3_GUARD + TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH) + 2;
    for (int i=start;i<TOX_MSGV3_MSGID_LENGTH;i++)
    {
        v[i] = (rand() % 254) + 1;
    }
}

void nt()
{
    v[v_size - 1] = 0;
}

void f()
{
    free(v);
    v = NULL;
}

int main(int argc, char *argv[])
{
    // Three-byte sequence (E0 80 80) is the broken sequence
    // and "AA" before that
    // NULL byte for null termination
    uint8_t broken_utf8_seq[6] = {0x41,0x41,0xe0,0x80,0x80,0x00};
    size_t broken_utf8_seq_len = 6;

    int n = 0;

    if (argc < 2)
    {
        return 1;
    }

    if (strlen(argv[1]) != (TOX_ADDRESS_SIZE * 2))
    {
        return 2;
    }

    printf("Killing Toxclient at ToxID: %s\n", argv[1]);

    stop_all = 0;

    struct Tox_Options options;
    tox_options_default(&options);

    tox1 = tox_new(&options, NULL);
    print_tox_id(tox1);
    const char gen_name[] = "Tox Client Killer";
    tox_self_set_name(tox1, (const uint8_t *)gen_name, strlen(gen_name), NULL);

	tox_callback_self_connection_status(tox1, self_connection_status);
	tox_callback_friend_request(tox1, friend_request);
    tox_callback_friend_read_receipt(tox1, friend_read_receipt);
    tox_callback_friend_connection_status(tox1, friend_connection_status);

	uint8_t address_bin1[TOX_ADDRESS_SIZE];
	tox_self_get_address(tox1, (uint8_t *)address_bin1);

	const char *key_hex1 = "1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976";
	uint8_t key_bin1[TOX_PUBLIC_KEY_SIZE];
	sodium_hex2bin(key_bin1, sizeof(key_bin1), key_hex1, strlen(key_hex1), NULL, NULL, NULL);
    tox_add_tcp_relay(tox1, "tox.verdict.gg", 33445, key_bin1, NULL);
    tox_bootstrap(tox1, "tox.verdict.gg", 33445, key_bin1, NULL);

    printf("  DEBUG:self bootstrapping ...\n");
	while (online1 == 0) {
		tox_iterate(tox1, NULL);

		long long time = tox_iteration_interval(tox1) * 1000000L;
		nanosleep((const struct timespec[]){{0, time}}, NULL);
	}
    printf("  DEBUG:self online\n");

	uint8_t address_bin2[TOX_ADDRESS_SIZE];
	sodium_hex2bin(address_bin2, sizeof(address_bin2), argv[1], strlen(argv[1]), NULL, NULL, NULL);
    printf("TEST-%d:%s\n", n, "friend request with invalid UTF-8");
    n++;
    tox_friend_add(tox1, address_bin2, (const uint8_t *)broken_utf8_seq, broken_utf8_seq_len, NULL);

    printf("  DEBUG:waiting for friend to accept and come online ...\n");
	while (online2 == 0) {
		tox_iterate(tox1, NULL);
		long long time = tox_iteration_interval(tox1) * 1000000L;
		nanosleep((const struct timespec[]){{0, time}}, NULL);
	}
    printf("  DEBUG:test client online\n");
    // ------------------------------------------------------------


    // ---------    message     ---------
    printf("TEST-%d:%s\n", n, "send text message with invalid UTF-8");
    n++;
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)broken_utf8_seq, broken_utf8_seq_len, NULL);
    it(tox1);

    printf("TEST-%d:%s\n", n, "send text message not NULL terminated");
    n++;
    c(100);
    ra();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "send text message NULL terminated");
    n++;
    c(100);
    ra();
    nt();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "send text message length TOX_MAX_MESSAGE_LENGTH not NULL terminated");
    n++;
    c(TOX_MAX_MESSAGE_LENGTH);
    ra();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "send text message length TOX_MAX_MESSAGE_LENGTH NULL terminated");
    n++;
    c(TOX_MAX_MESSAGE_LENGTH);
    ra();
    nt();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "send text message with msgV3 metadata");
    n++;
    c(100);
    ra();
    m3();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);
    // ---------    message     ---------


    // --------- status message ---------
    printf("TEST-%d:%s\n", n, "change own status message to invalid UTF-8");
    n++;
    tox_self_set_status_message(tox1, (const uint8_t *)broken_utf8_seq, broken_utf8_seq_len, NULL);
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own status message length TOX_MAX_STATUS_MESSAGE_LENGTH not NULL terminated");
    n++;
    c(TOX_MAX_STATUS_MESSAGE_LENGTH);
    ra();
    tox_self_set_status_message(tox1, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own status message length TOX_MAX_STATUS_MESSAGE_LENGTH NULL terminated");
    n++;
    c(TOX_MAX_STATUS_MESSAGE_LENGTH);
    ra();
    nt();
    tox_self_set_status_message(tox1, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);
    // --------- status message ---------


    // ---------     name       ---------
    printf("TEST-%d:%s\n", n, "change own name to invalid UTF-8");
    n++;
    tox_self_set_name(tox1, (const uint8_t *)broken_utf8_seq, broken_utf8_seq_len, NULL);
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own name length TOX_MAX_NAME_LENGTH not NULL terminated");
    n++;
    c(TOX_MAX_NAME_LENGTH);
    ra();
    tox_self_set_name(tox1, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own name length TOX_MAX_NAME_LENGTH NULL terminated");
    n++;
    c(TOX_MAX_NAME_LENGTH);
    ra();
    nt();
    tox_self_set_name(tox1, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own name NOT NULL terminated");
    n++;
    c(10);
    ra();
    tox_self_set_name(tox1, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own name length 0");
    n++;
    tox_self_set_name(tox1, (const uint8_t *)NULL, 0, NULL);
    it(tox1);
    // ---------     name       ---------


    // ------------------------------------------------------------
    printf("TEST-END:all done, killing tox. bye.\n");
    tox_kill(tox1);
    exit(0);
}

