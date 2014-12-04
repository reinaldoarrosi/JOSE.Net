using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JOSE.Net
{
    public enum JwsAlgorithm
    {
        None,
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512,
        PS256,
        PS384,
        PS512,
        ES256, // ECDSA using P-256 curve and SHA-256 hash 
        ES384, // ECDSA using P-384 curve and SHA-384 hash 
        ES512  // ECDSA using P-521 curve and SHA-512 hash 
    }
}
