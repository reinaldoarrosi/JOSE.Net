using JOSE.Net.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JOSE.Net
{
    public class JWS
    {
        #region Algorithms
        internal static Dictionary<JwsAlgorithm, IJwsAlgorithm> HashAlgorithms = new Dictionary<JwsAlgorithm, IJwsAlgorithm>
        {
            {JwsAlgorithm.None, new Plaintext()},
            {JwsAlgorithm.HS256, new HmacUsingSha("SHA256")},
            {JwsAlgorithm.HS384, new HmacUsingSha("SHA384")},
            {JwsAlgorithm.HS512, new HmacUsingSha("SHA512")},

            {JwsAlgorithm.RS256, new RsaUsingSha("SHA256")},
            {JwsAlgorithm.RS384, new RsaUsingSha("SHA384")},
            {JwsAlgorithm.RS512, new RsaUsingSha("SHA512")},

            {JwsAlgorithm.ES256, new EcdsaUsingSha(256)},
            {JwsAlgorithm.ES384, new EcdsaUsingSha(384)},
            {JwsAlgorithm.ES512, new EcdsaUsingSha(521)},

            {JwsAlgorithm.PS256, new RsaPssUsingSha(32)},
            {JwsAlgorithm.PS384, new RsaPssUsingSha(48)},
            {JwsAlgorithm.PS512, new RsaPssUsingSha(64)}
        }; 
        #endregion

        public static bool TryDeserialize(out JOSEObject jose, string token, object signingKey = null)
        {
            try
            {
                jose = Deserialize(token, signingKey);
                return true;
            }
            catch
            {
                jose = null;
                return false;
            }
        }

        public static JOSEObject Deserialize(string token, object signingKey = null)
        {
            Ensure.IsNotEmpty(token, "Incoming token expected to be in compact serialization form, not empty, whitespace or null.");

            byte[][] parts = Compact.Parse(token);

            if (parts.Length != 3)
                throw new JoseDeserializationException("Incoming token is not a JWS object.");

            byte[] header = parts[0];
            byte[] payload = parts[1];
            byte[] signature = parts[2];

            byte[] securedInput = Encoding.UTF8.GetBytes(Compact.Serialize(header, payload));

            var headerData = JSON.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(header));
            var algorithm = Helper.GetJwsAlgorithm((string)headerData["alg"]);

            if (algorithm != JwsAlgorithm.None)
                Ensure.IsNotNull(signingKey, "SigningKey expected to be not null.");

            if (!HashAlgorithms[algorithm].Verify(signature, securedInput, signingKey))
                throw new IntegrityException("Invalid signature.");

            string headerStr = Encoding.UTF8.GetString(header);
            string payloadStr = Encoding.UTF8.GetString(payload);

            return new JOSEObject(headerStr, payloadStr, signature);
        }

        public JwsAlgorithm Algorithm { get; private set; }
        public object SigningKey { get; private set; }
        public object Payload { get; private set; }
        public IDictionary<string, object> Headers { get; private set; }

        public JWS(JwsAlgorithm algorithm, object signingKey, string payload)
            : this(algorithm, signingKey, (object)payload)
        { }

        public JWS(JwsAlgorithm algorithm, object signingKey, JWE payload)
            : this(algorithm, signingKey, (object)payload)
        { }

        public JWS(JwsAlgorithm algorithm, object signingKey, JWS payload)
            : this(algorithm, signingKey, (object)payload)
        { }

        private JWS(JwsAlgorithm algorithm, object signingKey, object payload)
        {
            if (algorithm != JwsAlgorithm.None)
                Ensure.IsNotNull(signingKey, "SigningKey expected to be not null.");

            if (payload is string)
                Ensure.IsNotEmpty((string)payload, "Payload expected to be not empty, whitespace or null.");
            else
                Ensure.IsNotNull(payload, "Payload expected to be not null.");

            Algorithm = algorithm;
            SigningKey = signingKey;
            Payload = payload;
            Headers = new Dictionary<string, object>();
        }

        public string Serialize()
        {
            var jwsHeader = new Dictionary<string, object>(Headers);
            jwsHeader.Add("alg", Algorithm.GetName());

            byte[] headerBytes = Encoding.UTF8.GetBytes(JSON.Serialize(jwsHeader));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(PayloadToString());

            var bytesToSign = Encoding.UTF8.GetBytes(Compact.Serialize(headerBytes, payloadBytes));

            byte[] signature = HashAlgorithms[Algorithm].Sign(bytesToSign, SigningKey);

            return Compact.Serialize(headerBytes, payloadBytes, signature);
        }

        private string PayloadToString()
        {
            if (Payload is JWE)
                return (Payload as JWE).Serialize();
            else if (Payload is JWS)
                return (Payload as JWS).Serialize();
            else
                return (Payload as string);
        }
    }
}
