using Jose.exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jose
{
    public static class Helper
    {
        public static string GetName(this JwsAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case JwsAlgorithm.None : return "none";
                case JwsAlgorithm.HS256 : return "HS256";
                case JwsAlgorithm.HS384 : return "HS384";
                case JwsAlgorithm.HS512 : return "HS512";
                case JwsAlgorithm.RS256 : return "RS256";
                case JwsAlgorithm.RS384 : return "RS384";
                case JwsAlgorithm.RS512 : return "RS512";
                case JwsAlgorithm.ES256 : return "ES256";
                case JwsAlgorithm.ES384 : return "ES384";
                case JwsAlgorithm.ES512 : return "ES512";
                case JwsAlgorithm.PS256 : return "PS256";
                case JwsAlgorithm.PS384 : return "PS384";
                case JwsAlgorithm.PS512 : return "PS512";
                default: return string.Empty;
            }
        }

        public static string GetName(this JweEncryption algorithm)
        {
            switch (algorithm)
            {
                case JweEncryption.A128CBC_HS256: return "A128CBC-HS256";
                case JweEncryption.A192CBC_HS384: return "A192CBC-HS384";
                case JweEncryption.A256CBC_HS512: return "A256CBC-HS512";
                case JweEncryption.A128GCM: return "A128GCM";
                case JweEncryption.A192GCM: return "A192GCM";
                case JweEncryption.A256GCM: return "A256GCM";
                default: return string.Empty;
            }
        }

        public static string GetName(this JweAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case JweAlgorithm.RSA1_5 : return "RSA1_5";
                case JweAlgorithm.RSA_OAEP : return "RSA-OAEP";
                case JweAlgorithm.RSA_OAEP_256 : return "RSA-OAEP-256";
                case JweAlgorithm.DIR : return "dir";
                case JweAlgorithm.A128KW : return "A128KW";
                case JweAlgorithm.A192KW : return "A192KW";
                case JweAlgorithm.A256KW : return "A256KW";
                case JweAlgorithm.ECDH_ES : return "ECDH-ES";
                case JweAlgorithm.ECDH_ES_A128KW : return "ECDH-ES+A128KW";
                case JweAlgorithm.ECDH_ES_A192KW : return "ECDH-ES+A192KW";
                case JweAlgorithm.ECDH_ES_A256KW : return "ECDH-ES+A256KW";
                case JweAlgorithm.PBES2_HS256_A128KW : return "PBES2-HS256+A128KW";
                case JweAlgorithm.PBES2_HS384_A192KW : return "PBES2-HS384+A192KW";
                case JweAlgorithm.PBES2_HS512_A256KW : return "PBES2-HS512+A256KW";
                case JweAlgorithm.A128GCMKW : return "A128GCMKW";
                case JweAlgorithm.A192GCMKW : return "A192GCMKW";
                case JweAlgorithm.A256GCMKW : return "A256GCMKW";
                default: return string.Empty;
            }
        }

        public static string GetName(this JweCompression algorithm)
        {
            switch (algorithm)
            {
                case JweCompression.None : return "none";
                case JweCompression.DEF : return "DEF";
                default : return string.Empty;
            }
        }

        public static JwsAlgorithm GetJwsAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "none": return JwsAlgorithm.None;
                case "HS256": return JwsAlgorithm.HS256;
                case "HS384": return JwsAlgorithm.HS384;
                case "HS512": return JwsAlgorithm.HS512;
                case "RS256": return JwsAlgorithm.RS256;
                case "RS384": return JwsAlgorithm.RS384;
                case "RS512": return JwsAlgorithm.RS512;
                case "ES256": return JwsAlgorithm.ES256;
                case "ES384": return JwsAlgorithm.ES384;
                case "ES512": return JwsAlgorithm.ES512;
                case "PS256": return JwsAlgorithm.PS256;
                case "PS384": return JwsAlgorithm.PS384;
                case "PS512": return JwsAlgorithm.PS512;
                default: throw new InvalidAlgorithmException("unsupported algorithm");
            }
        }

        public static JweEncryption GetJweEncryption(string algorithm)
        {
            switch (algorithm)
            {
                case "A128CBC-HS256": return JweEncryption.A128CBC_HS256;
                case "A192CBC-HS384": return JweEncryption.A192CBC_HS384;
                case "A256CBC-HS512": return JweEncryption.A256CBC_HS512;
                case "A128GCM": return JweEncryption.A128GCM;
                case "A192GCM": return JweEncryption.A192GCM;
                case "A256GCM": return JweEncryption.A256GCM;
                default: throw new InvalidAlgorithmException("unsupported algorithm");
            }
        }

        public static JweAlgorithm GetJweAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "RSA1_5": return JweAlgorithm.RSA1_5;
                case "RSA-OAEP": return JweAlgorithm.RSA_OAEP;
                case "RSA-OAEP-256": return JweAlgorithm.RSA_OAEP_256;
                case "dir": return JweAlgorithm.DIR;
                case "A128KW": return JweAlgorithm.A128KW;
                case "A192KW": return JweAlgorithm.A192KW;
                case "A256KW": return JweAlgorithm.A256KW;
                case "ECDH-ES": return JweAlgorithm.ECDH_ES;
                case "ECDH-ES+A128KW": return JweAlgorithm.ECDH_ES_A128KW;
                case "ECDH-ES+A192KW": return JweAlgorithm.ECDH_ES_A192KW;
                case "ECDH-ES+A256KW": return JweAlgorithm.ECDH_ES_A256KW;
                case "PBES2-HS256+A128KW": return JweAlgorithm.PBES2_HS256_A128KW;
                case "PBES2-HS384+A192KW": return JweAlgorithm.PBES2_HS384_A192KW;
                case "PBES2-HS512+A256KW": return JweAlgorithm.PBES2_HS512_A256KW;
                case "A128GCMKW": return JweAlgorithm.A128GCMKW;
                case "A192GCMKW": return JweAlgorithm.A192GCMKW;
                case "A256GCMKW": return JweAlgorithm.A256GCMKW;
                default: throw new InvalidAlgorithmException("usupported algorithm");
            }
        }

        public static JweCompression GetJweCompression(string algorithm)
        {
            switch (algorithm)
            {
                case "DEF": return JweCompression.DEF;
                default: return JweCompression.None;
            }
        }
    }
}
