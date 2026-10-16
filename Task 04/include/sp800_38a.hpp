#pragma once
#include "common.hpp"
namespace lab {
Bytes ecb_encrypt(const AES&,const Bytes&,bool padding=true);
Bytes ecb_decrypt(const AES&,const Bytes&,bool padding=true);
Bytes cbc_encrypt(const AES&,const Bytes&,const Bytes& iv,bool padding=true);
Bytes cbc_decrypt(const AES&,const Bytes&,const Bytes& iv,bool padding=true);
Bytes cfb_encrypt(const AES&,const Bytes&,const Bytes& iv,int segment_bits=128);
Bytes cfb_decrypt(const AES&,const Bytes&,const Bytes& iv,int segment_bits=128);
Bytes ofb_crypt(const AES&,const Bytes&,const Bytes& iv);
Bytes ctr_crypt(const AES&,const Bytes&,const Bytes& initial_counter);
}
