//
//  main.cpp
//  supersocks
//
//  Created by Scott Deng on 7/25/15.
//  Copyright (c) 2015 github. All rights reserved.
//

#include <iostream>
#include "socks.h"

int main(int argc, const char * argv[]) {
    // insert code here...
    Server ss;
    if(argc == 2){
        Server ss (argv[1]);
    }
    else if(argc == 3){
        Server ss (argv[1],argv[2]);
    }
    else if(argc == 1)
    {
        Server ss ;
    }
    else
    {
        std::cerr<<"error on parameter"<<std::endl;
        return 0;
    }
    
    main_loop(ss); //pass by reference
    
    return 0;
}
