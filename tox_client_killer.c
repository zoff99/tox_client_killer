#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include <sodium.h>

#include <tox/tox.h>
#include <tox/toxav.h>

static Tox *tox1 = NULL;
static ToxAV *toxav1 = NULL;
int online1 = 0;
int online2 = 0;
int added_friend = 0;
int video_call_started = 0;
int video_call_ended = 0;
int stop_all = 0;
int count_sent = 0;
int count_rcv = 0;
int count_ack = 0;
int global_audio_bit_rate = 32; // kbit/sec
int global_video_bit_rate = 1600; // kbit/sec
const int iterate_loops = 10; //60;
const int av_iterate_loops = 20;

static uint8_t *v = NULL;
static size_t v_size = 0;

uint32_t s_r(const uint32_t upper_bound)
{
    return randombytes_uniform(upper_bound);
}

uint32_t n_r(const uint32_t upper_bound)
{
    return rand() % upper_bound;
}

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

void av_call(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
}

void av_call_state(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    printf("  DEBUG:av call state = %d\n", state);

    if (state & TOXAV_FRIEND_CALL_STATE_FINISHED)
    {
        video_call_ended = 1;
        printf("  DEBUG:av call state = TOXAV_FRIEND_CALL_STATE_FINISHED\n");
    }
    else if (state & TOXAV_FRIEND_CALL_STATE_ERROR)
    {
        printf("  DEBUG:av call state = TOXAV_FRIEND_CALL_STATE_ERROR\n");
    }
    else if (state & TOXAV_FRIEND_CALL_STATE_SENDING_A)
    {
        printf("  DEBUG:av call state = TOXAV_FRIEND_CALL_STATE_SENDING_A\n");
        video_call_started = 1;
    }
    else if (state & TOXAV_FRIEND_CALL_STATE_SENDING_V)
    {
        printf("  DEBUG:av call state = TOXAV_FRIEND_CALL_STATE_SENDING_V\n");
        video_call_started = 1;
    }
    else if (state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_A)
    {
        printf("  DEBUG:av call state = TOXAV_FRIEND_CALL_STATE_ACCEPTING_A\n");
    }
    else if (state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_V)
    {
        printf("  DEBUG:av call state = TOXAV_FRIEND_CALL_STATE_ACCEPTING_V\n");
    }
}

void av_audio_receive_frame(ToxAV *av, uint32_t friend_number, const int16_t *pcm, size_t sample_count,
        uint8_t channels, uint32_t sampling_rate, void *user_data)
{
}
void av_video_receive_frame(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
        const uint8_t *y, const uint8_t *u, const uint8_t *v, int32_t ystride, int32_t ustride, int32_t vstride,
        void *user_data)
{
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
    for (int j=0;j<iterate_loops;j++)
    {
        tox_iterate(tox, NULL);
        long long time = tox_iteration_interval(tox) * 1000000L;
        nanosleep((const struct timespec[]){{0, time}}, NULL);
    }
}

void itav(Tox *tox, ToxAV *toxav)
{
    for (int j=0;j<av_iterate_loops;j++)
    {
        tox_iterate(tox, NULL);
		toxav_iterate(toxav);
        long long time = 60 * 1000000L;
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
        // random value 1..255
        v[i] = (s_r(255)) + 1;
    }
}

void r0()
{
    for (int i=0; i < v_size; i++)
    {
        // random value 0..255
        v[i] = (s_r(256));
    }
}

void ra()
{
    for (int i=0; i < v_size; i++)
    {
        // random A..Z (uppercase)
        v[i] = 'A' + s_r(26);
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
        // random value 1..255
        v[i] = (s_r(255)) + 1;
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

void rvbuf(uint8_t *buf, size_t size)
{
    for (int i=0; i < size; i++)
    {
        // random value 1..255
        *buf = (uint8_t)((n_r(255)) + 1);
        buf++;
    }
}

void rvbuf0(uint8_t *buf, size_t size)
{
    for (int i=0; i < size; i++)
    {
        // random value 0..255
        *buf = (uint8_t)(n_r(256));
        buf++;
    }
}

void svr()
{
    /**
     * Send a video frame to a friend.
     *
     * Y - plane should be of size: height * width
     * U - plane should be of size: (height/2) * (width/2)
     * V - plane should be of size: (height/2) * (width/2)
     *
     * @param friend_number The friend number of the friend to which to send a video
     * frame.
     * @param width Width of the frame in pixels.
     * @param height Height of the frame in pixels.
     * @param y Y (Luminance) plane data.
     * @param u U (Chroma) plane data.
     * @param v V (Chroma) plane data.
     */
    TOXAV_ERR_SEND_FRAME error;

    // 3840 × 2160 -> 4K
    // 1920 x 1080 -> 1080p
    //
    //                 random value 1..1920
    uint16_t width =  (s_r(1920)) + 1;
    //                 random value 1..1080
    uint16_t height = (s_r(1080)) + 1;

    size_t y_size = width * height;
    size_t u_size = (height/2) * (width/2);
    size_t v_size = (height/2) * (width/2);
    uint8_t *y = calloc(1, y_size);
    uint8_t *u = calloc(1, u_size);
    uint8_t *v = calloc(1, v_size);
    rvbuf(y, y_size);
    rvbuf(u, u_size);
    rvbuf(v, v_size);
    toxav_video_send_frame(toxav1, 0, width, height, y, u, v, &error);
    free(y);
    free(u);    
    free(v);    
}

#define RTP_HEADER_SIZE 80
#define RTP_TYPE_VIDEO 193
#define RTP_PADDING_FIELDS 4

struct RTPHeader {
    unsigned ve: 2; /* Version has only 2 bits! */ // was called "protocol_version" in V3
    unsigned pe: 1; /* Padding */
    unsigned xe: 1; /* Extra header */
    unsigned cc: 4; /* Contributing sources count */
    unsigned ma: 1; /* Marker */
    unsigned pt: 7; /* Payload type */
    uint16_t sequnum;
    uint32_t timestamp;
    uint32_t ssrc;
    uint64_t flags;
    uint32_t offset_full;
    uint32_t data_length_full;
    uint32_t received_length_full;
    uint64_t frame_record_timestamp; /* when was this frame actually recorded (this is a relative value!) */
    int32_t  fragment_num; /* if using fragments, this is the fragment/partition number */
    uint32_t real_frame_num; /* unused for now */
    uint32_t encoder_bit_rate_used; /* what was the encoder bit rate used to encode this frame */
    uint32_t client_video_capture_delay_ms; /* how long did the client take to capture a video frame in ms */
    uint32_t rtp_packet_number; /* rtp packet number */
    uint16_t offset_lower; // used to be called "cpart"
    uint16_t data_length_lower; // used to be called "tlen"
};

struct RTPMessage {
    uint16_t len;
    struct RTPHeader header;
    uint8_t data[];
};

size_t lnet_pack_u16(uint8_t *bytes, uint16_t v)
{
    bytes[0] = (v >> 8) & 0xff;
    bytes[1] = v & 0xff;
    return sizeof(v);
}

size_t lnet_pack_u32(uint8_t *bytes, uint32_t v)
{
    uint8_t *p = bytes;
    p += lnet_pack_u16(p, (v >> 16) & 0xffff);
    p += lnet_pack_u16(p, v & 0xffff);
    return p - bytes;
}

size_t lnet_pack_u64(uint8_t *bytes, uint64_t v)
{
    uint8_t *p = bytes;
    p += lnet_pack_u32(p, (v >> 32) & 0xffffffff);
    p += lnet_pack_u32(p, v & 0xffffffff);
    return p - bytes;
}

size_t lrtp_header_pack(uint8_t *const rdata, const struct RTPHeader *header)
{
    uint8_t *p = rdata;
    *p = (header->ve & 3) << 6
         | (header->pe & 1) << 5
         | (header->xe & 1) << 4
         | (header->cc & 0xf);
    ++p;
    *p = (header->ma & 1) << 7
         | (header->pt & 0x7f);
    ++p;

    p += lnet_pack_u16(p, header->sequnum);
    p += lnet_pack_u32(p, header->timestamp);
    p += lnet_pack_u32(p, header->ssrc);
    p += lnet_pack_u64(p, header->flags);
    p += lnet_pack_u32(p, header->offset_full);
    p += lnet_pack_u32(p, header->data_length_full);
    p += lnet_pack_u32(p, header->received_length_full);

    // ---------------------------- //
    //      custom fields here      //
    // ---------------------------- //
    p += lnet_pack_u64(p, header->frame_record_timestamp);
    p += lnet_pack_u32(p, header->fragment_num);
    p += lnet_pack_u32(p, header->real_frame_num);
    p += lnet_pack_u32(p, header->encoder_bit_rate_used);
    p += lnet_pack_u32(p, header->client_video_capture_delay_ms);
    p += lnet_pack_u32(p, header->rtp_packet_number);
    // ---------------------------- //
    //      custom fields here      //
    // ---------------------------- //

    for (size_t i = 0; i < RTP_PADDING_FIELDS; ++i) {
        p += lnet_pack_u32(p, 0);
    }

    p += lnet_pack_u16(p, header->offset_lower);
    p += lnet_pack_u16(p, header->data_length_lower);
    return p - rdata;
}

void svpr()
{
    size_t length = 1000;
    uint8_t *data = calloc(1, length);
    rvbuf0(data, length);

    struct RTPHeader header = {0};
    header.ve = 2;  // this is unused in toxav
    header.pe = 0;
    header.xe = 0;
    header.cc = 0;
    header.ma = 0;
    header.pt = RTP_TYPE_VIDEO % 128;
    header.sequnum = 1;
    header.timestamp = 0;
    header.ssrc = 0;
    header.offset_lower = 0;
    header.data_length_lower = length;
    header.flags = 1 << 0;
    header.frame_record_timestamp = 0;
    header.fragment_num = 0;
    header.real_frame_num = 0;
    header.encoder_bit_rate_used = 0;
    header.client_video_capture_delay_ms = 0;
    uint16_t length_safe = (uint16_t)length;

    if (length > UINT16_MAX) {
        length_safe = UINT16_MAX;
    }

    header.data_length_lower = length_safe;
    header.data_length_full = length; // without header
    header.offset_lower = 0;
    header.offset_full = 0;

    size_t size_rdata = (length + RTP_HEADER_SIZE + 1);
    uint8_t *rdata = calloc(1, size_rdata);
    rdata[0] = RTP_TYPE_VIDEO;  // packet id == payload_type

    header.rtp_packet_number = 0;
    lrtp_header_pack(rdata + 1, &header);
    memcpy(rdata + 1 + RTP_HEADER_SIZE, data, length);

    TOX_ERR_FRIEND_CUSTOM_PACKET error;
    tox_friend_send_lossy_packet(tox1, 0, rdata, size_rdata, &error);

    free(rdata);
    free(data);
}

void tox_log_cb__custom(Tox *tox, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                        const char *message, void *user_data)
{
    printf("  C-TOXCORE:%d:%s:%d:%s:%s\n", (int)level, file, (int)line, func, message);
}

int main(int argc, char *argv[])
{
    // Three-byte sequence (E0 80 80) is the broken sequence
    // and "AA" before that
    // NULL byte for null termination
    uint8_t broken_utf8_seq[6] = {0x41,0x41,0xe0,0x80,0x80,0x00};
    size_t broken_utf8_seq_len = 6;

    int n = 0;
    int msg = 1;

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
    srandom(time(NULL));

    struct Tox_Options options;
    tox_options_default(&options);

    options.udp_enabled = true;
    options.ipv6_enabled = true;
    options.local_discovery_enabled = true;
    options.hole_punching_enabled = true;
    options.tcp_port = 0;
    options.log_callback = tox_log_cb__custom;

    tox1 = tox_new(&options, NULL);
    print_tox_id(tox1);
    const char gen_name[] = "Tox Client Killer";
    tox_self_set_name(tox1, (const uint8_t *)gen_name, strlen(gen_name), NULL);

	tox_callback_self_connection_status(tox1, self_connection_status);
	tox_callback_friend_request(tox1, friend_request);
    tox_callback_friend_read_receipt(tox1, friend_read_receipt);
    tox_callback_friend_connection_status(tox1, friend_connection_status);

    // -- init ToxAV --
    toxav1 = toxav_new(tox1, NULL);
    toxav_callback_call(toxav1, av_call, NULL);
    toxav_callback_call_state(toxav1, av_call_state, NULL);
    //toxav_callback_bit_rate_status(ToxAV *av, toxav_bit_rate_status_cb *callback, void *user_data);
    //toxav_callback_audio_bit_rate(ToxAV *av, toxav_audio_bit_rate_cb *callback, void *user_data);
    //toxav_callback_video_bit_rate(ToxAV *av, toxav_video_bit_rate_cb *callback, void *user_data);
    toxav_callback_audio_receive_frame(toxav1, av_audio_receive_frame, NULL);
    toxav_callback_video_receive_frame(toxav1, av_video_receive_frame, NULL);
    // -- init ToxAV --


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
    // ------ iterate for 7 more seconds (to get a stable connection) ------
    time_t start;
    time_t end;
    double elapsed;
    start = time(NULL);
	while (true) {
        end = time(NULL);
        elapsed = difftime(end, start);
        if (elapsed > 7)
        {
            break;
        }
		tox_iterate(tox1, NULL);
		long long time = tox_iteration_interval(tox1) * 1000000L;
		nanosleep((const struct timespec[]){{0, time}}, NULL);
	}
    // ------ iterate for 7 more seconds (to get a stable connection) ------
    printf("  DEBUG:test client online\n");
    // ---------------------------------------------------------------------

    const int run_loops = 10;
    for(int curloop=0;curloop<run_loops;curloop++)
    {

    // ---------    message     ---------
    // ---------    message     ---------
    // ---------    message     ---------
    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message with invalid UTF-8");
    msg++;
    n++;
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)broken_utf8_seq, broken_utf8_seq_len, NULL);
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message not NULL terminated");
    msg++;
    n++;
    c(100);
    ra();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message NULL terminated");
    msg++;
    n++;
    c(100);
    ra();
    nt();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message length TOX_MAX_MESSAGE_LENGTH not NULL terminated");
    msg++;
    n++;
    c(TOX_MAX_MESSAGE_LENGTH);
    ra();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message length TOX_MAX_MESSAGE_LENGTH NULL terminated");
    msg++;
    n++;
    c(TOX_MAX_MESSAGE_LENGTH);
    ra();
    nt();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message with msgV3 metadata");
    msg++;
    n++;
    c(100);
    ra();
    m3();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message with random bytes maybe NULL terminated (random byte at the end)");
    msg++;
    n++;
    c(TOX_MAX_MESSAGE_LENGTH / 2);
    r0();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message length TOX_MAX_MESSAGE_LENGTH with random bytes maybe NULL terminated (random byte at the end)");
    msg++;
    n++;
    c(TOX_MAX_MESSAGE_LENGTH);
    r0();
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message containing only NULL bytes");
    msg++;
    n++;
    c(TOX_MAX_MESSAGE_LENGTH / 2);
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:[M:%d]%s\n", n, msg, "send text message length TOX_MAX_MESSAGE_LENGTH containing only NULL bytes");
    msg++;
    n++;
    c(TOX_MAX_MESSAGE_LENGTH);
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);
    // ---------    message     ---------
    // ---------    message     ---------
    // ---------    message     ---------


    // --------- status message ---------
    // --------- status message ---------
    // --------- status message ---------
    printf("TEST-%d:%s\n", n, "change own status message to invalid UTF-8");
    n++;
    tox_self_set_status_message(tox1, (const uint8_t *)broken_utf8_seq, broken_utf8_seq_len, NULL);
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own status message length 0");
    n++;
    tox_self_set_status_message(tox1, (const uint8_t *)NULL, 0, NULL);
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
    // --------- status message ---------
    // --------- status message ---------


    // ---------     name       ---------
    // ---------     name       ---------
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

    printf("TEST-%d:%s\n", n, "change own name NULL terminated");
    n++;
    c(10);
    ra();
    nt();
    tox_self_set_name(tox1, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own name to random bytes maybe NULL terminated (random byte at the end)");
    n++;
    c(TOX_MAX_NAME_LENGTH / 2);
    r0();
    tox_self_set_name(tox1, (const uint8_t *)v, v_size, NULL);
    f();
    it(tox1);

    printf("TEST-%d:%s\n", n, "change own name length 0");
    n++;
    tox_self_set_name(tox1, (const uint8_t *)NULL, 0, NULL);
    it(tox1);
    // ---------     name       ---------
    // ---------     name       ---------
    // ---------     name       ---------

    }

    // ---------     VIDEO      ---------
    // ---------     VIDEO      ---------
    // ---------     VIDEO      ---------
    printf("  DEBUG:waiting for friend to accept video call ...\n");
    TOXAV_ERR_CALL av_call_error;
    bool res = toxav_call(toxav1, 0, global_audio_bit_rate, global_video_bit_rate, &av_call_error);
    printf("  DEBUG:start call : %d %d ...\n", res, av_call_error);
	while (video_call_started == 0) {
		tox_iterate(tox1, NULL);
		toxav_iterate(toxav1);
		long long time = tox_iteration_interval(tox1) * 1000000L;
		nanosleep((const struct timespec[]){{0, time}}, NULL);
	}
    printf("  DEBUG:video started\n");
    // ---------     VIDEO      ---------
    // ---------     VIDEO      ---------
    // ---------     VIDEO      ---------

    // ------ send random video data with random resolution for 12 seconds ------
    start = time(NULL);
	while (true) {
        end = time(NULL);
        elapsed = difftime(end, start);
        if (elapsed > 12)
        {
            break;
        }
		tox_iterate(tox1, NULL);
        svr();
		tox_iterate(tox1, NULL);
        toxav_iterate(toxav1);
		long long time = 40 * 1000000L; // 40ms =~ 25fps
		nanosleep((const struct timespec[]){{0, time}}, NULL);
	}
    // ------ send random video data with random resolution for 12 seconds ------

    // ------ send random video packets for 6 seconds ------
    start = time(NULL);
	while (true) {
        end = time(NULL);
        elapsed = difftime(end, start);
        if (elapsed > 6)
        {
            break;
        }
		tox_iterate(tox1, NULL);
        svpr();
		tox_iterate(tox1, NULL);
        toxav_iterate(toxav1);
		long long time = 40 * 1000000L; // 40ms =~ 25fps
		nanosleep((const struct timespec[]){{0, time}}, NULL);
	}
    // ------ send random video packets for 6 seconds ------

    itav(tox1, toxav1);
    toxav_call_control(toxav1, 0, TOXAV_CALL_CONTROL_CANCEL, NULL);
    itav(tox1, toxav1);
    printf("  DEBUG:video ended\n");

    // ------------------------------------------------------------
    printf("TEST-END:all done, killing tox. bye.\n");
    toxav_kill(toxav1);
    tox_iterate(tox1, NULL);
    tox_kill(tox1);
    exit(0);
}

