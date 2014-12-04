using System;
using System.Collections.Generic;
using System.Text;
using Jose.jwe;
using Jose.exceptions;

namespace Jose
{
    /// <summary>
    /// Provides methods for encoding and decoding JSON Web Tokens.
    /// </summary>
    public class JWT
    {
        public static JOSE Deserialize(string token, object signingKey = null, object encryptionKey = null)
        {
            JOSE jose;

            try
            {
                // try to deserialize as a JWS
                jose = JWS.Deserialize(token, signingKey); 
            }
            catch (JoseDeserializationException)
            {
                // if a deserialization error occurs, try to deserialize as a JWE
                jose = JWE.Deserialize(token, encryptionKey);
            }

            var jwtHeader = JSON.Parse<Dictionary<string, object>>(jose.Header);

            // if the JOSE Header contains a "cty" with value "JWT" it means that the payload is a nested JWT
            if (jwtHeader.ContainsKey("cty") && "JWT".Equals(jwtHeader["cty"] as string, StringComparison.OrdinalIgnoreCase))
                jose = Deserialize(jose.Payload, signingKey, encryptionKey);

            return jose;
        }

        public JwsAlgorithm? SigningAlgorithm { get; private set; }
        public object SigningKey { get; private set; }
        public JweAlgorithm? KeyAlgorithm { get; private set; }
        public JweEncryption? EncryptionAlgorithm { get; private set; }
        public object EncryptionKey { get; private set; }
        public JweCompression? CompressionAlgorithm { get; private set; }
        public object ClaimSet { get; private set; }

        public JWT(JwsAlgorithm signingAlgorithm, object signingKey, object claimSet)
        {
            if(signingAlgorithm != JwsAlgorithm.None)
                Ensure.IsNotNull(signingKey, "SigningKey is expected to be not null.");

            SigningAlgorithm = signingAlgorithm;
            SigningKey = signingKey;
            ClaimSet = claimSet;
        }

        public JWT(JweAlgorithm keyAlgorithm, JweEncryption encryptionAlgorithm, object encryptionKey, object claimSet)
        {
            Ensure.IsNotNull(encryptionKey, "EncryptionKey is expected to be not null.");

            KeyAlgorithm = keyAlgorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
            EncryptionKey = encryptionKey;
            ClaimSet = claimSet;
        }

        public JWT(JweAlgorithm keyAlgorithm, JweEncryption encryptionAlgorithm, JweCompression compressionAlgorithm, object encryptionKey, object claimSet)
        {
            Ensure.IsNotNull(encryptionKey, "EncryptionKey is expected to be not null.");

            KeyAlgorithm = keyAlgorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
            EncryptionKey = encryptionKey;
            CompressionAlgorithm = compressionAlgorithm;
            ClaimSet = claimSet;
        }

        public JWT(JwsAlgorithm signingAlgorithm, object signingKey, JweAlgorithm keyAlgorithm, JweEncryption encryptionAlgorithm, object encryptionKey, object claimSet)
        {
            Ensure.IsNotNull(encryptionKey, "EncryptionKey is expected to be not null.");

            if (signingAlgorithm != JwsAlgorithm.None)
                Ensure.IsNotNull(signingKey, "SigningKey is expected to be not null.");

            SigningAlgorithm = signingAlgorithm;
            SigningKey = signingKey;
            KeyAlgorithm = keyAlgorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
            EncryptionKey = encryptionKey;
            ClaimSet = claimSet;
        }

        public JWT(JwsAlgorithm signingAlgorithm, object signingKey, JweAlgorithm keyAlgorithm, JweEncryption encryptionAlgorithm, JweCompression compressionAlgorithm, object encryptionKey, object claimSet)
        {
            Ensure.IsNotNull(encryptionKey, "EncryptionKey is expected to be not null.");

            if (signingAlgorithm != JwsAlgorithm.None)
                Ensure.IsNotNull(signingKey, "SigningKey is expected to be not null.");

            SigningAlgorithm = signingAlgorithm;
            SigningKey = signingKey;
            KeyAlgorithm = keyAlgorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
            EncryptionKey = encryptionKey;
            CompressionAlgorithm = compressionAlgorithm;
            ClaimSet = claimSet;
        }

        public string SignedToken()
        {
            JWS jws = ConvertToJWS();
            jws.Headers["typ"] = "JWT";

            return jws.Serialize();
        }

        public string EncryptedToken()
        {
            JWE jwe = ConvertToJWE();
            jwe.Headers["typ"] = "JWT";

            return jwe.Serialize();
        }

        public string EncryptedAndSignedToken()
        {
            JWE jwe = ConvertToJWE();
            jwe.Headers["typ"] = "JWT";

            JWS jws = ConvertToJWS(jwe);
            jws.Headers["typ"] = "JWT";
            jwe.Headers["cty"] = "JWT";

            return jws.Serialize();
        }

        public string SignedAndEncryptedToken()
        {
            JWS jws = ConvertToJWS();
            jws.Headers["typ"] = "JWT";

            JWE jwe = ConvertToJWE(jws);
            jws.Headers["typ"] = "JWT";
            jwe.Headers["cty"] = "JWT";

            return jwe.Serialize();
        }

        public JWS ConvertToJWS()
        {
            return ConvertToJWS(SerializeClaimSet());
        }

        public JWE ConvertToJWE()
        {
            return ConvertToJWE(SerializeClaimSet());
        }

        private JWS ConvertToJWS(object payload)
        {
            Ensure.IsNotNull(SigningAlgorithm, "No signing algorithm (JwsAlgorithm) was set.");

            if(payload is JWE)
                return new JWS(SigningAlgorithm.Value, SigningKey, payload as JWE);
            else if(payload is JWS)
                return new JWS(SigningAlgorithm.Value, SigningKey, payload as JWS);
            else
                return new JWS(SigningAlgorithm.Value, SigningKey, payload as string);
        }

        private JWE ConvertToJWE(object payload)
        {
            Ensure.IsNotNull(KeyAlgorithm, "No key algorithm (JweAlgorithm) was set.");
            Ensure.IsNotNull(EncryptionAlgorithm, "No encryption algorithm (JweEncryption) was set.");

            JweCompression compressionAlgorithm = CompressionAlgorithm ?? JweCompression.None;

            if(payload is JWE)
                return new JWE(KeyAlgorithm.Value, EncryptionAlgorithm.Value, compressionAlgorithm, EncryptionKey, payload as JWE);
            else if (payload is JWS)
                return new JWE(KeyAlgorithm.Value, EncryptionAlgorithm.Value, compressionAlgorithm, EncryptionKey, payload as JWS);
            else
                return new JWE(KeyAlgorithm.Value, EncryptionAlgorithm.Value, compressionAlgorithm, EncryptionKey, payload as string);
        }

        private string SerializeClaimSet()
        {
            if (ClaimSet is string)
                return ClaimSet as string;
            else
                return JSON.Serialize(ClaimSet);
        }
    }
}
