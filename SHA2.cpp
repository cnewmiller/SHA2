//
//  SHA2.cpp
//  SHA2-256
//
//  Created by Clayton Newmiller on 5/23/16.
//  Copyright © 2016 Clayton Newmiller. All rights reserved.
//

#include "SHA2.hpp"
#include <iostream>

const unsigned int SHA2::k[64];


SHA2::SHA2(){
    
}

SHA2::~SHA2(){
    
}
unsigned int SHA2::convertHexToNum(unsigned char c) { //copied and modified from ConvertStringToBinary.java, given by Prof. Rogers
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    else {
        return 0;
    }
}
string SHA2::convertIntToHex(unsigned int l) { //copied and modified from ConvertStringToBinary.java, given by Prof. Rogers
    string ret="";
    unsigned char c;
    for (int i=7;i>=0;i--){
        c=(l>>(i*4))&0xf;
        if (c >= 0 && c <= 9) {
            c = c+'0';
        }
        else if (c >= 0xa && c <= 0xf) {
            c =(c + 'a' - 10);
        }
        else {
            c = '0';
        }
        ret+=c;
    }
    return ret;
}

unsigned int SHA2::ROTL(int num, int steps){
    unsigned int n=num;
    for (int i = 0; i<steps;i++){
        unsigned int bit = ((n & 0x80000000)>>31)&0x1;
        n = (n<<1)^(bit);
    }
    
    return n;
}
unsigned int SHA2::ROTR(int num, int steps){
    unsigned int n=num;
    for (int i = 0; i<steps;i++){
        unsigned int bit = (n &0x1)<<31;
//        cout<<bit<<endl;
        n = ((n>>1)&0x7fffffff)^(bit);
    }
    
    return n;
}


string SHA2::encrypt(string input){
    message_len = input.length();
    numofchunks = ((message_len+8)/64)+1;
    
    unsigned int messages [numofchunks][16];
    
    string m = input;
    unsigned char bit =0x80;
    m+=bit;//append 1 in bitwise form to the original string
    while(m.length()%64!=56){
        m+=(unsigned char)(0x0); //pad with 0s
    }
    
    for (int j=0;j<numofchunks;j++){for (int i=0;i<16;i++){messages[j][i]=0;}} //zero them out, perhaps unnecessarily
    
    for (int x=0;x<numofchunks-1;x++){ //process chunks up until the last chunk
        for (int i=0,j=0; i < 16; ++i, j += 4){
            messages[x][i] = (m[x*64+j] << 24) | (m[x*64+j+1] << 16) | (m[x*64+j+2] << 8) | (m[x*64+j+3]);
        }
        
    }
    for (int i=0,j=0; i <14; ++i, j += 4){ //process last chunk
        unsigned long x = numofchunks-1;
        messages[x][i] = ((m[x*64+j] << 24)&0xff000000) | ((m[x*64+j+1] << 16)&0xff0000) | ((m[x*64+j+2] << 8)&0xff00) | ((m[x*64+j+3])&0xff);
    }
    
    if (message_len<=0xffffffff){
        messages[numofchunks-1][15]=(message_len*8) & 0xffffffff;
    }
    else{
        messages[numofchunks-1][15]=(message_len*8) & 0xffffffff;
        messages[numofchunks-1][14]=(message_len*8)>>32 & 0xffffffff;
    }
    
    
//    parse_message(input, messages, numofchunks);
    
    unsigned int H[8]; //initial hash values
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;
    
    for (int chunk = 0; chunk<numofchunks;chunk++){
        //message expansion
        unsigned int words[64];
        for (int i=0;i<16;i++){
            words[i]=messages[chunk][i]; //copy into message schedule
        }
        for (int i=16;i<64;i++){
            unsigned int s0 = (ROTR(words[i-15], 7))^(ROTR(words[i-15],18))^((words[i-15]>>3)); //&0x1fffffff
            unsigned int s1 = (ROTR(words[i-2], 17))^(ROTR(words[i-2],19))^((words[i-2]>>10)); //&0x003fffff
            words[i] = (words[i-16]+words[i-7]+s0+s1);
        }
        unsigned int a = H[0], //declare working variables
            b = H[1],
            c = H[2],
            d = H[3],
            e = H[4],
            f = H[5],
            g = H[6],
            h = H[7];
        for (int i=0;i<64;i++){
            unsigned int s1 = (ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25));
            unsigned int ch = (e & f) ^ ((~e) & g); //weirdass bitwise problem
            unsigned int temp1 = h + s1 + ch + k[i] + words[i];
            unsigned int s0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
            unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
            unsigned int temp2 = s0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }
    string ret;
    for (int i=0;i<8;i++){
        ret+=convertIntToHex(H[i]);
    }

    return ret;
}






