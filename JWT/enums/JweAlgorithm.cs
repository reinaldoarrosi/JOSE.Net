using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JOSE.Net
{
    public enum JweAlgorithm
    {
        RSA1_5, //RSAES with PKCS #1 v1.5 padding, RFC 3447
        RSA_OAEP, //RSAES using Optimal Assymetric Encryption Padding, RFC 3447
        RSA_OAEP_256, //RSAES with SHA-256 using Optimal Assymetric Encryption Padding, RFC 3447
        DIR, //Direct use of pre-shared symmetric key
        A128KW, //AES Key Wrap Algorithm using 128 bit keys, RFC 3394
        A192KW, //AES Key Wrap Algorithm using 192 bit keys, RFC 3394
        A256KW,  //AES Key Wrap Algorithm using 256 bit keys, RFC 3394 
        ECDH_ES, //Elliptic Curve Diffie Hellman key agreement
        ECDH_ES_A128KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 128 bit key
        ECDH_ES_A192KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 192 bit key
        ECDH_ES_A256KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 256 bit key
        PBES2_HS256_A128KW, //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 128 bit key        
        PBES2_HS384_A192KW, //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 192 bit key        
        PBES2_HS512_A256KW,  //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 256 bit key        
        A128GCMKW,  //AES GCM Key Wrap Algorithm using 128 bit keys
        A192GCMKW,  //AES GCM Key Wrap Algorithm using 192 bit keys
        A256GCMKW   //AES GCM Key Wrap Algorithm using 256 bit keys
    }
}
