#include "packet_capture.h"
#include "../utils/logger.h"
#include "../core/packet_handler.h"
#include <pcap.h>
#include <string.h>

static pcap_t* handle = NULL;
static char errbuf[PCAP_ERRBUF_SIZE];
static int is_running = 0;

int init_packet_capture(const char* interface_name) {
    if (!interface_name) {
        // Если интерфейс не указан, найдем первый доступный
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            log_message(LOG_ERROR, "Error finding devices: %s", errbuf);
            return -1;
        }

        if (!alldevs) {
            log_message(LOG_ERROR, "No interfaces found!");
            return -1;
        }

        interface_name = alldevs->name;
        log_message(LOG_INFO, "Using interface: %s", interface_name);
    }

    // Открываем устройство
    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        log_message(LOG_ERROR, "Couldn't open device %s: %s", interface_name, errbuf);
        return -1;
    }

    // Устанавливаем фильтр для IP пакетов
    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        log_message(LOG_ERROR, "Couldn't parse filter %s: %s", filter_exp, pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        log_message(LOG_ERROR, "Couldn't install filter: %s", pcap_geterr(handle));
        return -1;
    }

    log_message(LOG_INFO, "Packet capture initialized on interface %s", interface_name);
    return 0;
}

static void packet_handler_callback(u_char* user,
                                  const struct pcap_pkthdr* header,
                                  const u_char* packet) {
    process_packet(packet, header);
}

int start_packet_capture(void) {
    if (!handle) {
        log_message(LOG_ERROR, "Packet capture not initialized");
        return -1;
    }

    if (is_running) {
        log_message(LOG_WARNING, "Packet capture already running");
        return 0;
    }

    is_running = 1;
    log_message(LOG_INFO, "Starting packet capture");

    // Запускаем захват пакетов в бесконечном цикле
    return pcap_loop(handle, 0, packet_handler_callback, NULL);
}

int stop_packet_capture(void) {
    if (!handle) {
        return 0;
    }

    if (is_running) {
        pcap_breakloop(handle);
        is_running = 0;
    }

    pcap_close(handle);
    handle = NULL;
    log_message(LOG_INFO, "Packet capture stopped");
    return 0;
}