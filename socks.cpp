//
//  socks.cpp
//  supersocks
//
//  Created by Scott Deng on 7/25/15.
//  Copyright (c) 2015 github. All rights reserved.
//

#include "socks.h"
#include <iostream>
#include <stdint.h>
bool acception(Server& ss);

bool client_decision(std::list<struct client>::iterator it, Server ss);
bool connection_establish(std::list<struct client>::iterator it, Server ss);
bool forward_to_remote(std::list<struct client>::iterator it, Server ss);
bool handshake(std::list<struct client>::iterator it, Server ss);

bool forward_to_client(std::list<struct remote>::iterator it, Server ss);


static inline int connection_establishment(addrinfo *addr);

static inline void set_port(sockaddr *addr, uint16_t port){
        ((sockaddr_in*)addr)->sin_port = port;
}
static inline int connection_establishment(addrinfo *addr){
    int sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if(sock < 0){
        close(sock);
        return -1;
    }
    
    int rc = connect(sock,addr->ai_addr, addr->ai_addrlen);
    if(rc != 0){
        close(sock);
        return -1;
    }
    
    int flags = fcntl(sock, F_GETFL, 0);
    if(flags < 0){
        close(sock);
        return -1;
    }
    if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0){
        close(sock);
        return  -1;
    }
    
    return sock;
}





bool handshake(std::list<struct client>::iterator it, Server ss){
    struct authentication auth;
    
    auto len = recv(it->child, ss.buffer,10, NULL); //modify me
    
    if(len < 4){
        close(it->child);
        return false;
    }
    auth.version = ss.buffer[0];
    auth.is_authentication = ss.buffer[1];
    auth.authentication_key = ss.buffer[2] + ss.buffer[3];
    
    /*modify me*/
    if(auth.is_authentication == 0x01 && auth.authentication_key == 0x002e && auth.version == 0x10){
        int16_t success = 0xeeee;
        send(it->child,&success,2,NULL);
        it->cd = waiting;
        memset(ss.buffer, 0, 10);
        return true;
    }
    else{
        int16_t failed = 0x0000;
        send(it->child,&failed, 2, NULL);
        memset(ss.buffer, 0, 10);
        close(it->child);
        return false;
    }
}

bool connection_establish(std::list<struct client>::iterator it, Server ss){
    auto len = recv(it->child, ss.buffer,10, NULL); //modify me
    if(len < 4){
        memset(ss.buffer, 0 , 10);
        return false;
    }
    struct remote_info cr;
    
    if(ss.buffer[0] != 0x10){
        close(it->child);
        return false;
    }
    if(ss.buffer[1] != 0X02){
        close(it->child);
        return false;
    }
    if(ss.buffer[2] != 0x00){
        close(it->child);
        return false;
    }
    
    cr.address_type = ss.buffer[3];
    int sock;
    
    switch(cr.address_type){
        case 0x01:
            struct addrinfo *addr;
            cr.addr = (char *)operator new(4);
            memcpy(cr.addr, ss.buffer + 4, 4);
            memcpy(&cr.port_num,ss.buffer+8,2);
            getaddrinfo(NULL, NULL, NULL, &addr);
            
            addr->ai_addrlen =4;
            memcpy(addr->ai_addr->sa_data, cr.addr, 4);
            addr->ai_family = AF_INET;
            addr->ai_socktype = SOCK_STREAM;
            addr->ai_protocol = 0;
            
            sock = connection_establishment(addr);
            if(sock < 0){
                it->cd = erroring;
                freeaddrinfo(addr);
                delete [] cr.addr;
                memset(ss.buffer, 0, 10);
                return false;
            }
            else{
                struct remote rmt;
                rmt.clnt = it;
                rmt.rmt = sock;
                ss.rmt.push_back(rmt);
                it->rmt = ss.rmt.end();
                it->cd = reading;
                freeaddrinfo(addr);
                delete [] cr.addr;
                memset(ss.buffer, 0, 10);
                return true;
            }
            break;
        case 0x04:
            struct addrinfo *addr1;
            cr.addr = (char *) operator new(16);
            memcpy(cr.addr, ss.buffer +4, 16);
            memcpy(&cr.port_num, ss.buffer + 19, 2);
            
            getaddrinfo(NULL, NULL, NULL, &addr1);
            memcpy(addr1->ai_addr->sa_data, cr.addr, 16);
            addr1->ai_addr->sa_len = 16;
            addr1->ai_addrlen = 16;
            set_port(addr1->ai_addr, cr.port_num);
            addr1->ai_socktype = SOCK_STREAM;
            addr1->ai_protocol = 0;
            addr1->ai_family = AF_INET6;
            
            sock = connection_establishment(addr);
            if(sock < 0){
                it->cd = erroring;
                freeaddrinfo(addr1);
                delete [] cr.addr;
                memset(ss.buffer, 0, 10);
                return false;
            }
            else{
                struct remote rmt;
                rmt.clnt = it;
                rmt.rmt = sock;
                ss.rmt.push_back(rmt);
                it->rmt = ss.rmt.end();
                it->cd = reading;
                freeaddrinfo(addr1);
                delete [] cr.addr;
                memset(ss.buffer, 0, 10);
                return true;
            }
            break;
        case 0x03:
            struct addrinfo *addr2;
            cr.addr_len = ss.buffer[4];
            cr.addr = (char*) operator new(cr.addr_len*sizeof(char));
            memcpy(cr.addr,ss.buffer+4,cr.addr_len*sizeof(char));
            memcpy(&cr.port_num, ss.buffer + 3+ cr.addr_len*sizeof(char), 2*sizeof(char));
            
            getaddrinfo(cr.addr, NULL, NULL, &addr2);
            addr2->ai_socktype = SOCK_STREAM;
            addr2->ai_protocol = 0;
            addr2->ai_family = AF_UNSPEC;
            set_port(addr2->ai_addr, cr.port_num);
            
            sock = connection_establishment(addr);
            if(sock < 0){
                it->cd = erroring;
                freeaddrinfo(addr2);
                delete [] cr.addr;
                memset(ss.buffer, 0, 10);
                return false;
            }
            else{
                struct remote rmt;
                rmt.clnt = it;
                rmt.rmt = sock;
                ss.rmt.push_back(rmt);
                it->rmt = ss.rmt.end();
                it->cd = reading;
                freeaddrinfo(addr2);
                delete [] cr.addr;
                memset(ss.buffer, 0, 10);
                return true;
            }
            break;
        default:
            return false;
            break;
    }
} //no deleting from list

bool forward_to_remote(std::list<struct client>::iterator it, Server ss){
    auto len = recv(it->child, ss.buffer, MAX_BUFFER,NULL);
    if(len<= 0){
        close(it->child);
        close(it->rmt->rmt);
        return false;
    }
    
    auto len2 = send(it->rmt->rmt, ss.buffer, len, NULL);
    if(len != len2){
        close(it->child);
        close(it->rmt->rmt);
        return false;
    }
    return true;
}

bool client_decision(std::list<struct client>::iterator it, Server ss){
    if(it->cd == initialing) return handshake(it, ss);
    else if(it->cd == waiting) return connection_establish(it, ss);
    else if(it->cd == reading) return forward_to_remote(it, ss);
    else return 0;
}


void main_loop(Server& ss){
    while(1){
        ss.select_all();
        /*acception*/
        if(ss.read_is_set(ss.parent_socket)){
            if(!acception(ss)){
                std::cerr<<"error on accept a client"<<std::endl;
            }
            else std::cout<<"new connections"<<std::endl;
        }
        /*from client handshake or forward to remote*/
        
        std::list<struct client>::iterator del_client;
        bool dele_client = false;
        for(auto it = ss.clnt.begin();it != ss.clnt.end();it++){
            if(ss.read_is_set(it->child)){
                if(!client_decision(it, ss)){
                    del_client = it;
                    dele_client = true;
                }
                break;
            }
        }
        
        if(dele_client){
            if(del_client->cd == reading){
                ss.rmt.erase(del_client->rmt);
                ss.clnt.erase(del_client);
            }
            else{
                ss.clnt.erase(del_client);
            }
        }
        
        /*from remote forward to client*/
        decltype(ss.rmt.begin()) del_remote;
        bool dele_remote = false;
        for(auto it = ss.rmt.begin();it != ss.rmt.end();it++){
            if(ss.read_is_set(it->rmt)){
                if(!forward_to_client(it, ss)){
                    del_remote = it;
                    dele_remote = true;
                }
            }
        }
        if(dele_remote){
            ss.clnt.erase(del_remote->clnt);
            ss.rmt.erase(del_remote);
        }
    }
}

bool acception(Server& ss){
    struct client clnt;
    clnt.child = accept(ss.parent_socket, NULL, NULL);
    if(clnt.child < 0){
        close(clnt.child);
        return false;
    }
    clnt.cd = initialing;
    ss.clnt.push_back(clnt);
    ss.fd_set_add(clnt.child);
    return true;
}

bool forward_to_client(std::list<struct remote>::iterator it, Server ss){
    auto len = recv(it->rmt, ss.buffer, MAX_BUFFER, NULL);
    if(len <= 0){
        close(it->clnt->child);
        close(it->rmt);
        return false;
    }
    auto len1 = send(it->clnt->child, ss.buffer, len,NULL);
    if(len1 != len){
        close(it->rmt);
        close(it->clnt->child);
        return false;
    }
    return true;
}


