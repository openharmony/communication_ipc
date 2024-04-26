/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "rpc_socket_trans.h"

#include <netinet/in.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "lwip/def.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"

#include "rpc_errno.h"
#include "rpc_log.h"
#include "securec.h"
#include "utils_list.h"

#define DEVICEID_LENGTH 64
#define SERVICENAME_LENGTH 200
#define DEFAULT_LOCAL_DEVICEID "192.168.1.74"
#define DEFAULT_THREAD_STACK_SIZE 8192

typedef struct {
    UTILS_DL_LIST list;
    char *saSessionName;
    char *deviceId;
    TransCallback cb;
} SocketNode;

typedef struct {
    UTILS_DL_LIST list;
    pthread_mutex_t mutex;
} SocketNodeList;

static SocketNodeList g_socketNodeList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static int32_t g_init = -1;
static int32_t g_serverCreated = -1;
static TransCallback g_callback;
static char *g_localDeviceId = NULL;

static uint16_t Hash(const char *name)
{
    if (name == NULL) {
        return 0;
    }
    RPC_LOG_INFO("Hash called %s", name);
    sleep(1);

    uint16_t hash = DEFAULT_HASH_SEED;
    uint16_t c;

    while (c = *name++)
        hash = ((hash << DEFAULT_HASH_OFFSET) + hash) + c;

    return hash % DEFAULT_PORT_MIN + DEFAULT_PORT_MIN;
}

static int32_t BindLocalIP(int fd, const char *localIP, uint16_t port, struct sockaddr_in *addr)
{
    if (memset_s(addr, sizeof(struct sockaddr_in), 0, sizeof(*addr)) != EOK) {
        RPC_LOG_ERROR("sockaddr_in memset failed");
        return ERR_FAILED;
    }

    addr->sin_family = AF_INET;
    int rc = inet_pton(AF_INET, localIP, &addr->sin_addr);
    if (rc <= 0) {
        RPC_LOG_ERROR("inet_pton rc=%d", rc);
        return ERR_FAILED;
    }
    addr->sin_port = lwip_htons(port);

    errno = 0;
    rc = bind(fd, (struct sockaddr *)addr, sizeof(*addr));
    if (rc < 0) {
        RPC_LOG_ERROR("bind fd=%d,rc=%d", fd, rc);
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static void TcpShutDown(int fd)
{
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}

static void *HandleAccept(void *args)
{
    pthread_setname_np(pthread_self(), "h_rpc_req");
    if (args == NULL) {
        return NULL;
    }
    int32_t clientFd = *(int32_t *)args;
    int32_t ret;
    if (g_callback.OnConnected != NULL) {
        ret = g_callback.OnConnected(clientFd, 0);
        if (ret != ERR_NONE) {
            RPC_LOG_ERROR("g_callback OnConnected failed");
            return NULL;
        }
    }

    char buf[DEFAULT_PACKET_SIZE];
    if (g_callback.OnRecieved != NULL) {
        for (; ;) {
            ssize_t readLen = read(clientFd, buf, DEFAULT_PACKET_SIZE);
            if (readLen == 0) {
                RPC_LOG_INFO("client socket close");
                g_callback.OnDisconnected(clientFd);
                TcpShutDown(clientFd);
                return NULL;
            }
            if (readLen < 0) {
                RPC_LOG_ERROR("socket read error=%d", readLen);
                TcpShutDown(clientFd);
                return NULL;
            }
            ret = g_callback.OnRecieved(clientFd, (void *)buf, (uint32_t)readLen);
            if (ret != ERR_NONE) {
                RPC_LOG_ERROR("g_callback OnRecieved failed");
                return NULL;
            }
        }
    }
    return NULL;
}

static void *OpenTcpServerSocket(void *args)
{
    if (args == NULL) {
        return NULL;
    }
    printf("OpenTcpServerSocket %lu\n", strlen((char *)args));
    sleep(1);

    char *ip = (char *)SOCKET_SERVER_ADDR;
    uint16_t port = Hash((char *)args);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        RPC_LOG_ERROR("fd=%d", fd);
        return NULL;
    }

    struct sockaddr_in addr;
    int32_t ret = BindLocalIP(fd, ip, port, &addr);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("BindLocalIP ret=%d", ret);
        TcpShutDown(fd);
        return NULL;
    }

    if (listen(fd, DEFAULT_BACKLOG) != 0) {
        RPC_LOG_ERROR("listen failed");
        TcpShutDown(fd);
        return NULL;
    }

    g_serverCreated = 0;
    for (; ;) {
        socklen_t len = sizeof(addr);
        int32_t clientFd = accept(fd, (struct sockaddr *)&addr, &len);
        RPC_LOG_INFO("accept get fd %d", clientFd);

        pthread_t threadId;
        pthread_attr_t threadAttr;
        ret = pthread_attr_init(&threadAttr);
        if (ret != 0) {
            RPC_LOG_ERROR("pthread_attr_init failed %d", ret);
            return ERR_FAILED;
        }

        if (pthread_attr_setstacksize(&threadAttr, DEFAULT_THREAD_STACK_SIZE) != 0) {
            RPC_LOG_ERROR("pthread_attr_setstacksize failed");
            return ERR_FAILED;
        }

        ret = pthread_create(&threadId, &threadAttr, HandleAccept, (void *)&clientFd);
        if (ret != 0) {
            RPC_LOG_ERROR("pthread_create failed %d", ret);
            return ERR_FAILED;
        }
        pthread_detach(threadId);
    }
    return NULL;
}

static int32_t StartListen(const char *saSessionName, void *cb)
{
    if (saSessionName == NULL) {
        RPC_LOG_ERROR("saSessionName is null");
        return ERR_FAILED;
    }
    if (memcpy_s(&g_callback, sizeof(TransCallback), cb, sizeof(TransCallback)) != EOK) {
        RPC_LOG_ERROR("g_callback memcpy_s failed");
        return ERR_FAILED;
    }

    pthread_t threadId;
    pthread_attr_t threadAttr;
    int ret = pthread_attr_init(&threadAttr);
    if (ret != 0) {
        RPC_LOG_ERROR("pthread_attr_init failed %d", ret);
        return ERR_FAILED;
    }

    if (pthread_attr_setstacksize(&threadAttr, DEFAULT_THREAD_STACK_SIZE) != 0) {
        RPC_LOG_ERROR("pthread_attr_setstacksize failed");
        return ERR_FAILED;
    }

    ret = pthread_create(&threadId, &threadAttr, OpenTcpServerSocket, (void *)saSessionName);
    if (ret != 0) {
        RPC_LOG_ERROR("pthread_create failed %d", ret);
        return ERR_FAILED;
    }
    pthread_detach(threadId);

    return ERR_NONE;
}

static int32_t StopListen(const char *saSessionName)
{
    return ERR_NONE;
}

static void *HandleSendReply(void *args)
{
    pthread_setname_np(pthread_self(), "h_rpc_r");
    if (args == NULL) {
        RPC_LOG_ERROR("HandleSendReply args is null");
        return NULL;
    }
    int32_t fd = *(int32_t *)args;
    free(args);

    char buf[DEFAULT_PACKET_SIZE];
    if (g_callback.OnRecieved != NULL) {
        for (; ;) {
            ssize_t readLen = read(fd, buf, DEFAULT_PACKET_SIZE);
            if (readLen == 0) {
                RPC_LOG_INFO("HandleSendReply received len %d", readLen);
                g_callback.OnDisconnected(fd);
                TcpShutDown(fd);
                return NULL;
            }
            if (readLen < 0) {
                RPC_LOG_ERROR("HandleSendReply received len %d", readLen);
                TcpShutDown(fd);
                return NULL;
            }
            g_callback.OnRecieved(fd, buf, readLen);
        }
    }
    return NULL;
}

static int32_t HandleConnect(int32_t fd)
{
    int32_t *sessionId = (int32_t *)malloc(sizeof(int32_t));
    if (sessionId == NULL) {
        return ERR_FAILED;
    }

    *sessionId = fd;
    pthread_t threadId;
    pthread_attr_t threadAttr;
    int ret = pthread_attr_init(&threadAttr);
    if (ret != 0) {
        RPC_LOG_ERROR("pthread_attr_init failed %d", ret);
        free(sessionId);
        return ERR_FAILED;
    }

    if (pthread_attr_setstacksize(&threadAttr, DEFAULT_THREAD_STACK_SIZE) != 0) {
        RPC_LOG_ERROR("pthread_attr_setstacksize failed");
        free(sessionId);
        return ERR_FAILED;
    }

    ret = pthread_create(&threadId, &threadAttr, HandleSendReply, (void *)sessionId);
    if (ret != 0) {
        RPC_LOG_ERROR("pthread_create failed %d", ret);
        return ERR_FAILED;
    }
    pthread_detach(threadId);

    return fd;
}

static int32_t Connect(const char *saSessionName, const char *peerDeviceId, void *args)
{
    (void)args;
    if (saSessionName == NULL) {
        RPC_LOG_INFO("saSessionName is null");
        return ERR_FAILED;
    }
    uint16_t port = Hash(saSessionName);

    int32_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        RPC_LOG_ERROR("%s:%d:fd=%d", __func__, __LINE__, fd);
        return ERR_FAILED;
    }

    struct sockaddr_in addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        RPC_LOG_ERROR("memset failed");
    }
    addr.sin_family = AF_INET;
    int rc = inet_pton(AF_INET, peerDeviceId, &addr.sin_addr);
    if (rc <= 0) {
        RPC_LOG_ERROR("inet_pton rc=%d", rc);
        return ERR_FAILED;
    }
    addr.sin_port = lwip_htons(port);
    errno = 0;

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if ((rc == -1) && (errno != EINPROGRESS)) {
        RPC_LOG_ERROR("fd=%d,connect rc=%d, errno=%d", fd, rc, errno);
        TcpShutDown(fd);
        return ERR_FAILED;
    }

    return HandleConnect(fd);
}

static int32_t Disconnect(int32_t sessionId)
{
    (void)sessionId;
    return ERR_NONE;
}

static int32_t Send(int32_t sessionId, const void *data, uint32_t len)
{
    if (sessionId < 0 || data == NULL || len <= 0) {
        RPC_LOG_ERROR("send invail params");
        return ERR_FAILED;
    }

    ssize_t ret = write(sessionId, data, len);
    if (ret < 0) {
        RPC_LOG_ERROR("send error=%d", ret);
        return ERR_FAILED;
    }

    return ERR_NONE;
}

static int32_t GetSocketLocalDeviceID(const char *saSessionName, char *deviceId)
{
    extern struct netif if_wifi;
    const ip4_addr_t *ip4Addr = netif_ip4_addr(&if_wifi);
    char *localDeviceId = ip4addr_ntoa(ip4Addr);
    if (localDeviceId == NULL) {
        RPC_LOG_ERROR("GetSocketLocalDeviceID inet_ntoa return null");
        return ERR_FAILED;
    }
    if (memcpy_s(deviceId, DEVICEID_LENGTH + 1, localDeviceId, DEVICEID_LENGTH + 1) != EOK) {
        RPC_LOG_ERROR("GetSocketLocalDeviceID memcpy failed");
        free(localDeviceId);
        return ERR_FAILED;
    }
    RPC_LOG_INFO("GetSocketLocalDeviceID %s\n", deviceId);
    return ERR_NONE;
}

static TransInterface g_socketTrans = {
    .StartListen = StartListen,
    .StopListen = StopListen,
    .Connect = Connect,
    .Disconnect = Disconnect,
    .Send = Send,
    .GetLocalDeviceID = GetSocketLocalDeviceID
};

TransInterface *GetSocketTrans(void)
{
    if (g_init == -1) {
        pthread_mutex_lock(&g_socketNodeList.mutex);
        UtilsListInit(&g_socketNodeList.list);
        g_init = 0;
        printf("g_socketTrans %x\n", g_socketTrans.StartListen);
        pthread_mutex_unlock(&g_socketNodeList.mutex);
    }
    return &g_socketTrans;
}