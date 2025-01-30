cmake_minimum_required(VERSION 3.20)
project(firewall C)

set(CMAKE_C_STANDARD 11)

# Определяем пути
set(EXTERN_DIR ${CMAKE_SOURCE_DIR}/extern)
set(NPCAP_DIR ${EXTERN_DIR}/npcap)
set(NET_HEADERS_DIR ${EXTERN_DIR}/net_headers)
set(CJSON_DIR ${EXTERN_DIR}/cJSON)

# Проверяем архитектуру
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_DIR "x64")
else()
    set(ARCH_DIR "x86")
endif()

# Добавляем и настраиваем cJSON
add_subdirectory(${CJSON_DIR})

# Отключаем строгие проверки для cJSON
target_compile_options(cjson PRIVATE
        -Wno-float-conversion
        -Wno-error=float-conversion
)

# Включаем заголовочные файлы
include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/utils
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/network
        ${NPCAP_DIR}/Include
        ${NET_HEADERS_DIR}
        ${CJSON_DIR}
)

# Добавляем пути к библиотекам
link_directories(${NPCAP_DIR}/Lib/${ARCH_DIR})

# Определяем исходные файлы
set(SOURCES
        src/main.c
        src/core/firewall.c
        src/core/packet_handler.c
        src/core/rule_manager.c
        src/network/packet_capture.c
        src/utils/logger.c
        src/utils/config.c
)

# Создаем исполняемый файл
add_executable(${PROJECT_NAME} ${SOURCES})

# Добавляем определение для Windows
if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
            WIN32_LEAN_AND_MEAN
            _WIN32_WINNT=0x0601
            WINVER=0x0601
    )
endif()

# Линкуем необходимые библиотеки
target_link_libraries(${PROJECT_NAME}
        wpcap
        Packet
        ws2_32
        cjson
)

# Создаем директорию config если её нет
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/config)

# Копируем конфигурационные файлы
configure_file(${CMAKE_SOURCE_DIR}/config/firewall_config.json
        ${CMAKE_BINARY_DIR}/config/firewall_config.json
        COPYONLY
)

# Добавляем пост-сборочные команды для копирования DLL
if(WIN32)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:cjson>
            $<TARGET_FILE_DIR:${PROJECT_NAME}>
    )
endif()