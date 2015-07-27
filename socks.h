//
//  socks.h
//  supersocks
//
//  Created by Scott Deng on 7/25/15.
//  Copyright (c) 2015 github. All rights reserved.
//

#ifndef __supersocks__socks__
#define __supersocks__socks__

#include <istream>
#include <stdint.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <list>
#include <string>
#include <sys/select.h>


#define MAX_BUFFER 10*1024

struct authentication{
    uint8_t version;
    uint8_t is_authentication;
    uint16_t authentication_key;
};


struct auth_feedback{
    
};

//----------------------------------------------------------------------
enum cndt{initialing = 0,reading = 1,waiting = 3,erroring =4};

struct remote_info{
    uint8_t address_type; //1 byte
    uint8_t addr_len; //only for domain
    char *addr; //multiple byte for domain,  4 byte for ipv4, 16 byte for ipv6,
    uint16_t port_num; //2 byte
};

struct client{
    enum cndt cd;
    int child;
    std::list<struct remote>::iterator rmt;
};

struct remote{
    int rmt;
    std::list<struct client>::iterator clnt;
};



struct Server{
public:
    const char *port; //default port number
    int parent_socket;
    char *buffer;
    std::string key;
    bool encryped;
    int client_number;
    const int backlog = 20;
    
    
    Server(){
        buffer =(char *)operator new(MAX_BUFFER);
        FD_ZERO(&sets.rset_rgn);
        FD_ZERO(&sets.wset_rgn);
        port = "1984";
        client_number = 0;
        start_server();
        FD_SET(parent_socket, &sets.rset_rgn);
        FD_SET(parent_socket, &sets.wset_rgn);
        sets.max_fd = parent_socket;
    }
    Server(const char *port_num){
        buffer =(char *)operator new(MAX_BUFFER);
        FD_ZERO(&sets.rset_rgn);
        FD_ZERO(&sets.wset_rgn);
        port = port_num;
        client_number = 0;
        start_server();
        FD_SET(parent_socket, &sets.rset_rgn);
        FD_SET(parent_socket, &sets.wset_rgn);
        sets.max_fd = parent_socket;
    }
    Server(const char *port_num, const std::string keys){
        buffer =(char *)operator new(MAX_BUFFER);
        FD_ZERO(&sets.rset_rgn);
        FD_ZERO(&sets.wset_rgn);
        port = port_num;
        key = keys;
        client_number = 0;
        start_server();
        FD_SET(parent_socket, &sets.rset_rgn);
        FD_SET(parent_socket, &sets.wset_rgn);
        sets.max_fd = parent_socket;
    }
    
    std::list<struct remote> rmt;
    std::list<struct client> clnt;
    
    void fd_set_add(int i){
        FD_SET(i, &sets.rset_rgn);
        FD_SET(i, &sets.wset_rgn);
    }
    
    int select_all(){
        sets.rset_v = sets.rset_rgn;
        sets.wset_v = sets.wset_rgn;
        
        int rc = select(sets.max_fd + 1 , &sets.rset_v, NULL,NULL, NULL);
        return rc;
    }
    
    void erase_client(struct client eraser){
        FD_CLR(eraser.child, &sets.rset_rgn);
        FD_CLR(eraser.child, &sets.wset_rgn);
        
    }
    bool read_is_set(int i) const {
        return FD_ISSET(i,&sets.rset_v);
    }
    bool write_is_set(int i) const {
        return FD_ISSET(i,&sets.wset_v);
    }
    
private:
    struct entire_set{
        fd_set rset_rgn;
        fd_set rset_v;
        fd_set wset_rgn;
        fd_set wset_v;
        int max_fd;
    }sets;
    bool start_server(){
        struct addrinfo *server_addr = NULL;
        
        if(getaddrinfo(NULL,port,NULL,&server_addr) != 0) {
            freeaddrinfo(server_addr);
            return false;
        }
        server_addr->ai_family = AF_INET;
        server_addr->ai_socktype = SOCK_STREAM;
        server_addr->ai_protocol = IPPROTO_TCP;
        server_addr->ai_flags = AI_PASSIVE;
        
        parent_socket = socket(server_addr->ai_family, server_addr->ai_socktype,server_addr->ai_protocol);
        if(parent_socket < 0){
            freeaddrinfo(server_addr);
            return false;
        }
        int yes = 1;
        int rc = setsockopt(parent_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if(rc == -1){
            freeaddrinfo(server_addr);
            return false;
        }
        
        if(bind(parent_socket,server_addr->ai_addr,server_addr->ai_addrlen) < 0){
            freeaddrinfo(server_addr);
            return false;
        }
        if(listen(parent_socket,backlog) < 0){
            freeaddrinfo(server_addr);
            return false;
        }
        
        freeaddrinfo(server_addr);
        return true;
    }
};


void main_loop(Server& ss);
#endif /* defined(__supersocks__socks__) */
