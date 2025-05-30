// Copyright (c) 2025 Synrc Research Center

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>

#define MQTT_PORT 1883
#define MQTT_TLS_PORT 8883
#define MQTT_QUIC_PORT 14567
#define MAX_CLIENTS 10000
#define BUFFER_SIZE 8192

enum mqtt_packet_type {
    MQTT_CONNECT = 1,
    MQTT_CONNACK = 2,
    MQTT_PUBLISH = 3,
    MQTT_PUBACK = 4,
    MQTT_PUBREC = 5,
    MQTT_PUBREL = 6,
    MQTT_PUBCOMP = 7,
    MQTT_SUBSCRIBE = 8,
    MQTT_SUBACK = 9,
    MQTT_UNSUBSCRIBE = 10,
    MQTT_UNSUBACK = 11,
    MQTT_PINGREQ = 12,
    MQTT_PINGRESP = 13,
    MQTT_DISCONNECT = 14,
    MQTT_AUTH = 15
};

typedef struct {
    uint8_t property_id;
    union {
        uint8_t byte;
        uint32_t integer;
        char *string;
        struct { char *name; char *value; } pair;
    } value;
} mqtt_property_t;

typedef struct {
    mqtt_property_t *properties;
    size_t count;
} mqtt_properties_t;

enum mqtt_property_id {
    MQTT_PROP_PAYLOAD_FORMAT = 1,
    MQTT_PROP_MESSAGE_EXPIRY = 2,
    MQTT_PROP_SUBSCRIPTION_ID = 11,
    MQTT_PROP_SESSION_EXPIRY = 17,
    MQTT_PROP_AUTH_METHOD = 21,
    MQTT_PROP_AUTH_DATA = 22,
};

typedef struct {
    uv_tcp_t handle;
    mbedtls_ssl_context ssl;
    int is_tls;
    int is_quic;
    char buffer[BUFFER_SIZE];
    size_t buffer_len;
    char client_id[256];
    int connected;
    uint8_t qos;
    char will_topic[256];
    char will_message[256];
    uint32_t session_expiry;      // MQTT v5 session expiry
    uint16_t packet_id;           // Track packet IDs for QoS
    mqtt_properties_t properties; // MQTT v5 properties
    char *subscriptions[256];     // Track subscriptions
    size_t subscription_count;
} mqtt_client_t;

typedef struct {
    uv_loop_t *loop;
    uv_tcp_t tcp_server;
    uv_tcp_t tls_server;
    uv_udp_t udp_server;
    mqtt_client_t clients[MAX_CLIENTS];
    mbedtls_ssl_config ssl_conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    char *retained_topics[1024];
    char *retained_messages[1024];
    size_t retained_count;
} mqtt_server_t;

mqtt_server_t server;

int decode_remaining_length(const char *data, size_t len, size_t *remaining_len) {
    size_t multiplier = 1;
    size_t value = 0;
    size_t pos = 0;
    do {
        if (pos >= len) return -1;
        value += (data[pos] & 0x7F) * multiplier;
        multiplier *= 128;
        if (multiplier > 128 * 128 * 128 * 128) return -1; // Max 4 bytes
    } while ((data[pos++] & 0x80) != 0);
    *remaining_len = value;
    return pos;
}

int encode_remaining_length(char *buffer, size_t value) {
    int pos = 0;
    do {
        uint8_t byte = value % 128;
        value /= 128;
        if (value > 0) byte |= 0x80;
        buffer[pos++] = byte;
    } while (value > 0);
    return pos;
}

int decode_properties(const char *data, size_t len, size_t *pos, mqtt_properties_t *props) {
    if (*pos >= len) return -1;
    size_t prop_len;
    *pos += decode_remaining_length(data + *pos, len - *pos, &prop_len);
    size_t end = *pos + prop_len;
    props->count = 0;
    props->properties = NULL;
    while (*pos < end && *pos < len) {
        props->properties = realloc(props->properties, (props->count + 1) * sizeof(mqtt_property_t));
        mqtt_property_t *prop = &props->properties[props->count];
        prop->property_id = data[(*pos)++];
        switch (prop->property_id) {
            case MQTT_PROP_SESSION_EXPIRY:
            case MQTT_PROP_MESSAGE_EXPIRY:
                if (*pos + 4 > len) return -1;
                prop->value.integer = (data[*pos] << 24) | (data[*pos + 1] << 16) |
                                     (data[*pos + 2] << 8) | data[*pos + 3];
                *pos += 4;
                break;
            case MQTT_PROP_AUTH_METHOD:
            case MQTT_PROP_AUTH_DATA:
                if (*pos + 2 > len) return -1;
                uint16_t str_len = (data[*pos] << 8) | data[*pos + 1];
                *pos += 2;
                if (*pos + str_len > len) return -1;
                prop->value.string = strndup(&data[*pos], str_len);
                *pos += str_len;
                break;
            default:
                return -1; // Unsupported property
        }
        props->count++;
    }
    return 0;
}

int encode_properties(char *buffer, size_t *pos, mqtt_properties_t *props) {
    size_t start = *pos;
    *pos += 1; // Placeholder for property length
    for (size_t i = 0; i < props->count; i++) {
        mqtt_property_t *prop = &props->properties[i];
        buffer[(*pos)++] = prop->property_id;
        switch (prop->property_id) {
            case MQTT_PROP_SESSION_EXPIRY:
            case MQTT_PROP_MESSAGE_EXPIRY:
                buffer[(*pos)++] = (prop->value.integer >> 24) & 0xFF;
                buffer[(*pos)++] = (prop->value.integer >> 16) & 0xFF;
                buffer[(*pos)++] = (prop->value.integer >> 8) & 0xFF;
                buffer[(*pos)++] = prop->value.integer & 0xFF;
                break;
            case MQTT_PROP_AUTH_METHOD:
            case MQTT_PROP_AUTH_DATA:
                uint16_t str_len = strlen(prop->value.string);
                buffer[(*pos)++] = (str_len >> 8) & 0xFF;
                buffer[(*pos)++] = str_len & 0xFF;
                memcpy(&buffer[*pos], prop->value.string, str_len);
                *pos += str_len;
                break;
        }
    }
    size_t prop_len = *pos - start - 1;
    encode_remaining_length(buffer + start, prop_len);
    return 0;
}

int mbedtls_uv_send(void *ctx, const unsigned char *buf, size_t len) {
    uv_stream_t *stream = (uv_stream_t *)ctx;
    uv_buf_t uv_buf = uv_buf_init((char *)buf, len);
    uv_write_t *write_req = malloc(sizeof(uv_write_t));
    int ret = uv_write(write_req, stream, &uv_buf, 1, NULL);
    if (ret < 0) {
        free(write_req);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return len;
}

int mbedtls_uv_recv(void *ctx, unsigned char *buf, size_t len) {
    mqtt_client_t *client = (mqtt_client_t *)ctx;
    if (client->buffer_len == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    size_t to_copy = len < client->buffer_len ? len : client->buffer_len;
    memcpy(buf, client->buffer, to_copy);
    memmove(client->buffer, client->buffer + to_copy, client->buffer_len - to_copy);
    client->buffer_len -= to_copy;
    return to_copy;
}

void on_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(BUFFER_SIZE);
    buf->len = BUFFER_SIZE;
}

void on_close(uv_handle_t *handle) {
    mqtt_client_t *client = (mqtt_client_t *)handle->data;
    if (client->is_tls) {
        mbedtls_ssl_free(&client->ssl);
    }
    for (size_t i = 0; i < client->subscription_count; i++) {
        free(client->subscriptions[i]);
    }
    client->subscription_count = 0;
    client->connected = 0;
    free(handle);
}

int setup_tls(mqtt_server_t *server) {
    const char *pers = "mqtt_server";
    mbedtls_entropy_init(&server->entropy);
    mbedtls_ctr_drbg_init(&server->ctr_drbg);
    mbedtls_ssl_config_init(&server->ssl_conf);

    if (mbedtls_ctr_drbg_seed(&server->ctr_drbg, mbedtls_entropy_func, &server->entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0) {
        return -1;
    }

    if (mbedtls_ssl_config_defaults(&server->ssl_conf, MBEDTLS_SSL_IS_SERVER,
                                   MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        return -1;
    }

    mbedtls_ssl_conf_rng(&server->ssl_conf, mbedtls_ctr_drbg_random, &server->ctr_drbg);

    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&key);

    if (mbedtls_x509_crt_parse_file(&cert, "server.crt") != 0 ||
        mbedtls_pk_parse_keyfile(&key, "server.key", NULL) != 0) {
        return -1;
    }

    if (mbedtls_ssl_conf_own_cert(&server->ssl_conf, &cert, &key) != 0) {
        return -1;
    }

    return 0;
}

int parse_mqtt_packet(mqtt_client_t *client, const char *data, size_t len) {
    if (len < 2) return -1;
    uint8_t packet_type = (data[0] >> 4) & 0xF;
    size_t remaining_len;
    size_t pos = decode_remaining_length(data + 1, len - 1, &remaining_len);
    if (pos < 0 || pos + remaining_len > len) return -1;
    pos++;

    mqtt_properties_t props = {0};
    switch (packet_type) {
        case MQTT_CONNECT: {
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            uint16_t protocol_len = (data[pos] << 8) | data[pos + 1];
            pos += 2 + protocol_len;
            uint8_t connect_flags = data[pos++];
            if (connect_flags & 0x80) { // Will flag
                uint16_t will_topic_len = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                strncpy(client->will_topic, &data[pos], will_topic_len);
                client->will_topic[will_topic_len] = '\0';
                pos += will_topic_len;
                if (decode_properties(data, len, &pos, &props) < 0) return -1; // Will properties
                uint16_t will_msg_len = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                strncpy(client->will_message, &data[pos], will_msg_len);
                client->will_message[will_msg_len] = '\0';
                pos += will_msg_len;
            }
            uint16_t client_id_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            strncpy(client->client_id, &data[pos], client_id_len);
            client->client_id[client_id_len] = '\0';
            client->connected = 1;

            for (size_t i = 0; i < props.count; i++) {
                if (props.properties[i].property_id == MQTT_PROP_SESSION_EXPIRY) {
                    client->session_expiry = props.properties[i].value.integer;
                }
            }

            char connack[32] = { MQTT_CONNACK << 4, 0, 0, 0 }; // Success
            size_t connack_pos = 2;
            mqtt_properties_t connack_props = {0};
            encode_properties(connack, &connack_pos, &connack_props);
            connack[1] = connack_pos - 2; // Remaining length
            uv_buf_t buf = uv_buf_init(connack, connack_pos);
            uv_write_t *write_req = malloc(sizeof(uv_write_t));
            uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            free(props.properties);
            return 0;
        }
        case MQTT_PUBLISH: {
            uint8_t qos = (data[0] >> 1) & 0x3;
            size_t start_pos = pos;
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            uint16_t topic_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            char topic[256];
            strncpy(topic, &data[pos], topic_len);
            topic[topic_len] = '\0';
            pos += topic_len;
            uint16_t packet_id = 0;
            if (qos > 0) {
                packet_id = (data[pos] << 8) | data[pos + 1];
                pos += 2;
            }
            const char *message = &data[pos];
            size_t message_len = len - pos;

            if (data[0] & 0x1) { // Retain
                server.retained_topics[server.retained_count] = strdup(topic);
                server.retained_messages[server.retained_count] = strndup(message, message_len);
                server.retained_count++;
            }

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (server.clients[i].connected && &server.clients[i] != client) {
                    for (size_t j = 0; j < server.clients[i].subscription_count; j++) {
                        if (strcmp(server.clients[i].subscriptions[j], topic) == 0) {
                            uv_buf_t buf = uv_buf_init((char *)data, len);
                            uv_write_t *write_req = malloc(sizeof(uv_write_t));
                            uv_write(write_req, (uv_stream_t *)&server.clients[i].handle, &buf, 1, NULL);
                        }
                    }
                }
            }

            if (qos == 1) {
                char puback[32] = { MQTT_PUBACK << 4, 0, (packet_id >> 8) & 0xFF, packet_id & 0xFF };
                size_t puback_pos = 2;
                mqtt_properties_t puback_props = {0};
                encode_properties(puback, &puback_pos, &puback_props);
                puback[1] = puback_pos - 2;
                uv_buf_t buf = uv_buf_init(puback, puback_pos);
                uv_write_t *write_req = malloc(sizeof(uv_write_t));
                uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            } else if (qos == 2) {
                char pubrec[32] = { MQTT_PUBREC << 4, 0, (packet_id >> 8) & 0xFF, packet_id & 0xFF };
                size_t pubrec_pos = 2;
                mqtt_properties_t pubrec_props = {0};
                encode_properties(pubrec, &pubrec_pos, &pubrec_props);
                pubrec[1] = pubrec_pos - 2;
                uv_buf_t buf = uv_buf_init(pubrec, pubrec_pos);
                uv_write_t *write_req = malloc(sizeof(uv_write_t));
                uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            }
            free(props.properties);
            return 0;
        }
        case MQTT_PUBACK:
        case MQTT_PUBCOMP: {
            uint16_t packet_id = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            // Acknowledge QoS 1 or QoS 2 completion (clear stored message)
            free(props.properties);
            return 0;
        }
        case MQTT_PUBREC: {
            uint16_t packet_id = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            char pubrel[32] = { MQTT_PUBREL << 4 | 0x2, 0, (packet_id >> 8) & 0xFF, packet_id & 0xFF };
            size_t pubrel_pos = 2;
            mqtt_properties_t pubrel_props = {0};
            encode_properties(pubrel, &pubrel_pos, &pubrel_props);
            pubrel[1] = pubrel_pos - 2;
            uv_buf_t buf = uv_buf_init(pubrel, pubrel_pos);
            uv_write_t *write_req = malloc(sizeof(uv_write_t));
            uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            free(props.properties);
            return 0;
        }
        case MQTT_PUBREL: {
            uint16_t packet_id = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            char pubcomp[32] = { MQTT_PUBCOMP << 4, 0, (packet_id >> 8) & 0xFF, packet_id & 0xFF };
            size_t pubcomp_pos = 2;
            mqtt_properties_t pubcomp_props = {0};
            encode_properties(pubcomp, &pubcomp_pos, &pubcomp_props);
            pubcomp[1] = pubcomp_pos - 2;
            uv_buf_t buf = uv_buf_init(pubcomp, pubcomp_pos);
            uv_write_t *write_req = malloc(sizeof(uv_write_t));
            uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            free(props.properties);
            return 0;
        }
        case MQTT_SUBSCRIBE: {
            uint16_t packet_id = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            while (pos < len) {
                uint16_t topic_len = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                char topic[256];
                strncpy(topic, &data[pos], topic_len);
                topic[topic_len] = '\0';
                pos += topic_len;
                client->subscriptions[client->subscription_count++] = strdup(topic);
                client->qos = data[pos++]; // QoS level

                for (size_t i = 0; i < server.retained_count; i++) {
                    if (strcmp(server.retained_topics[i], topic) == 0) {
                        uv_buf_t buf = uv_buf_init(server.retained_messages[i], strlen(server.retained_messages[i]));
                        uv_write_t *write_req = malloc(sizeof(uv_write_t));
                        uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
                    }
                }
            }
            char suback[32] = { MQTT_SUBACK << 4, 0, (packet_id >> 8) & 0xFF, packet_id & 0xFF, client->qos };
            size_t suback_pos = 4;
            mqtt_properties_t suback_props = {0};
            encode_properties(suback, &suback_pos, &suback_props);
            suback[1] = suback_pos - 2;
            uv_buf_t buf = uv_buf_init(suback, suback_pos);
            uv_write_t *write_req = malloc(sizeof(uv_write_t));
            uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            free(props.properties);
            return 0;
        }
        case MQTT_UNSUBSCRIBE: {
            uint16_t packet_id = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            while (pos < len) {
                uint16_t topic_len = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                char topic[256];
                strncpy(topic, &data[pos], topic_len);
                topic[topic_len] = '\0';
                pos += topic_len;
                for (size_t i = 0; i < client->subscription_count; i++) {
                    if (strcmp(client->subscriptions[i], topic) == 0) {
                        free(client->subscriptions[i]);
                        client->subscriptions[i] = client->subscriptions[--client->subscription_count];
                        break;
                    }
                }
            }
            char unsuback[32] = { MQTT_UNSUBACK << 4, 0, (packet_id >> 8) & 0xFF, packet_id & 0xFF };
            size_t unsuback_pos = 4;
            mqtt_properties_t unsuback_props = {0};
            encode_properties(unsuback, &unsuback_pos, &unsuback_props);
            unsuback[1] = unsuback_pos - 2;
            uv_buf_t buf = uv_buf_init(unsuback, unsuback_pos);
            uv_write_t *write_req = malloc(sizeof(uv_write_t));
            uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            free(props.properties);
            return 0;
        }
        case MQTT_PINGREQ: {
            char pingresp[] = { MQTT_PINGRESP << 4, 0 };
            uv_buf_t buf = uv_buf_init(pingresp, 2);
            uv_write_t *write_req = malloc(sizeof(uv_write_t));
            uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            return 0;
        }
        case MQTT_DISCONNECT: {
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            uv_close((uv_handle_t *)&client->handle, on_close);
            free(props.properties);
            return 0;
        }
        case MQTT_AUTH: {
            if (decode_properties(data, len, &pos, &props) < 0) return -1;
            char *auth_method = NULL, *auth_data = NULL;
            for (size_t i = 0; i < props.count; i++) {
                if (props.properties[i].property_id == MQTT_PROP_AUTH_METHOD) {
                    auth_method = props.properties[i].value.string;
                } else if (props.properties[i].property_id == MQTT_PROP_AUTH_DATA) {
                    auth_data = props.properties[i].value.string;
                }
            }
            if (strcmp(auth_method, "SCRAM-SHA-1") == 0) {
                // Implement SCRAM-SHA-1 logic (requires external library or custom implementation)
                // For now, accept authentication
                char auth[32] = { MQTT_AUTH << 4, 0, 0 }; // Success
                size_t auth_pos = 2;
                mqtt_properties_t auth_props = {0};
                encode_properties(auth, &auth_pos, &auth_props);
                auth[1] = auth_pos - 2;
                uv_buf_t buf = uv_buf_init(auth, auth_pos);
                uv_write_t *write_req = malloc(sizeof(uv_write_t));
                uv_write(write_req, (uv_stream_t *)&client->handle, &buf, 1, NULL);
            }
            free(props.properties);
            return 0;
        }
        default:
            free(props.properties);
            return -1;
    }
}

void on_write(uv_write_t *req, int status) {
    free(req);
}


void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    mqtt_client_t *client = (mqtt_client_t *)stream->data;
    if (nread > 0) {
        if (client->is_tls) {
            client->buffer_len = nread;
            memcpy(client->buffer, buf->base, nread);
            mbedtls_ssl_set_bio(&client->ssl, client, mbedtls_uv_send, mbedtls_uv_recv, NULL);
            unsigned char tls_buf[BUFFER_SIZE];
            int ret = mbedtls_ssl_read(&client->ssl, tls_buf, nread);
            if (ret > 0) {
                parse_mqtt_packet(client, (const char *)tls_buf, ret);
            }
        } else {
            parse_mqtt_packet(client, buf->base, nread);
        }
    } else if (nread < 0) {
        if (client->connected && client->will_topic[0]) {
            char will_packet[512];
            size_t pos = 0;
            will_packet[pos++] = MQTT_PUBLISH << 4;
            size_t len = strlen(client->will_topic) + strlen(client->will_message) + 4;
            pos += encode_remaining_length(will_packet + pos, len);
            will_packet[pos++] = (strlen(client->will_topic) >> 8) & 0xFF;
            will_packet[pos++] = strlen(client->will_topic) & 0xFF;
            strcpy(&will_packet[pos], client->will_topic);
            pos += strlen(client->will_topic);
            strcpy(&will_packet[pos], client->will_message);
            pos += strlen(client->will_message);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (server.clients[i].connected && &server.clients[i] != client) {
                    uv_buf_t will_buf = uv_buf_init(will_packet, pos);
                    uv_write_t *write_req = malloc(sizeof(uv_write_t));
                    uv_write(write_req, (uv_stream_t *)&server.clients[i].handle, &will_buf, 1, NULL);
                }
            }
        }
        uv_close((uv_handle_t *)stream, on_close);
    }
    free(buf->base);
}

void on_connection(uv_stream_t *server_stream, int status) {
    if (status < 0) return;

    mqtt_server_t *server = (mqtt_server_t *)server_stream->data;
    mqtt_client_t *client = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!server->clients[i].connected) {
            client = &server->clients[i];
            break;
        }
    }
    if (!client) return;

    uv_tcp_t *client_handle = malloc(sizeof(uv_tcp_t));
    uv_tcp_init(server->loop, client_handle);
    client_handle->data = client;
    client->handle = *client_handle;
    client->connected = 1;
    client->is_tls = (server_stream == (uv_stream_t *)&server->tls_server);
    client->is_quic = 0;

    if (client->is_tls) {
        mbedtls_ssl_init(&client->ssl);
        if (mbedtls_ssl_setup(&client->ssl, &server->ssl_conf) != 0) {
            uv_close((uv_handle_t *)client_handle, on_close);
            return;
        }
    }

    if (uv_accept(server_stream, (uv_stream_t *)client_handle) == 0) {
        uv_read_start((uv_stream_t *)client_handle, on_alloc_buffer, on_read);
    } else {
        uv_close((uv_handle_t *)client_handle, on_close);
    }
}

void cleanup_server(mqtt_server_t *server) {
    for (size_t i = 0; i < server->retained_count; i++) {
        free(server->retained_topics[i]);
        free(server->retained_messages[i]);
    }
    server->retained_count = 0;
    mbedtls_ssl_config_free(&server->ssl_conf);
    mbedtls_ctr_drbg_free(&server->ctr_drbg);
    mbedtls_entropy_free(&server->entropy);
}

void on_udp_read(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread > 0) {
        mqtt_client_t temp_client = {0};
        parse_mqtt_packet(&temp_client, buf->base, nread);
    }
    free(buf->base);
}

void quic_stub(mqtt_server_t *server) {
    fprintf(stderr, "QUIC support requires msquic integration\n");
}

int main() {
    server.loop = uv_default_loop();
    memset(server.clients, 0, sizeof(server.clients));
    server.retained_count = 0;

    uv_tcp_init(server.loop, &server.tcp_server);
    struct sockaddr_in addr;
    uv_ip4_addr("0.0.0.0", MQTT_PORT, &addr);
    uv_tcp_bind(&server.tcp_server, (const struct sockaddr *)&addr, 0);
    server.tcp_server.data = &server;
    uv_listen((uv_stream_t *)&server.tcp_server, 128, on_connection);

    if (setup_tls(&server) == 0) {
        uv_tcp_init(server.loop, &server.tls_server);
        uv_ip4_addr("0.0.0.0", MQTT_TLS_PORT, &addr);
        uv_tcp_bind(&server.tls_server, (const struct sockaddr *)&addr, 0);
        server.tls_server.data = &server;
        uv_listen((uv_stream_t *)&server.tls_server, 128, on_connection);
    }

    uv_udp_init(server.loop, &server.udp_server);
    uv_ip4_addr("0.0.0.0", MQTT_PORT, &addr);
    uv_udp_bind(&server.udp_server, (const struct sockaddr *)&addr, 0);
    uv_udp_recv_start(&server.udp_server, on_alloc_buffer, on_udp_read);

    quic_stub(&server);

    printf("MQTT v5 server running on ports %d (TCP), %d (TLS), %d (UDP)\n", MQTT_PORT, MQTT_TLS_PORT, MQTT_QUIC_PORT);
    int ret = uv_run(server.loop, UV_RUN_DEFAULT);
    cleanup_server(&server);
    return ret;
}
