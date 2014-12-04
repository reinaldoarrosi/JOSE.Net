using JOSE.Net.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JOSE.Net
{
    public class JWE
    {
        #region Algorithms
        internal static Dictionary<JweEncryption, IJweAlgorithm> EncryptionAlgorithms = new Dictionary<JweEncryption, IJweAlgorithm>
        {
            {JweEncryption.A128CBC_HS256, new AesCbcHmacEncryption(JWS.HashAlgorithms[JwsAlgorithm.HS256], 256)},
            {JweEncryption.A192CBC_HS384, new AesCbcHmacEncryption(JWS.HashAlgorithms[JwsAlgorithm.HS384], 384)},
            {JweEncryption.A256CBC_HS512, new AesCbcHmacEncryption(JWS.HashAlgorithms[JwsAlgorithm.HS512], 512)},

            {JweEncryption.A128GCM, new AesGcmEncryption(128)},
            {JweEncryption.A192GCM, new AesGcmEncryption(192)},
            {JweEncryption.A256GCM, new AesGcmEncryption(256)}
        };

        internal static Dictionary<JweAlgorithm, IKeyManagement> KeyAlgorithms = new Dictionary<JweAlgorithm, IKeyManagement>
        {
            {JweAlgorithm.RSA1_5, new RsaKeyManagement(false)},
            {JweAlgorithm.RSA_OAEP, new RsaKeyManagement(true)},
            {JweAlgorithm.RSA_OAEP_256, new RsaKeyManagement(true,true)},
            {JweAlgorithm.DIR, new DirectKeyManagement()},
            {JweAlgorithm.A128KW, new AesKeyWrapManagement(128)},
            {JweAlgorithm.A192KW, new AesKeyWrapManagement(192)},
            {JweAlgorithm.A256KW, new AesKeyWrapManagement(256)},
            {JweAlgorithm.ECDH_ES, new EcdhKeyManagement(true)},
            {JweAlgorithm.ECDH_ES_A128KW, new EcdhKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128))},
            {JweAlgorithm.ECDH_ES_A192KW, new EcdhKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192))},
            {JweAlgorithm.ECDH_ES_A256KW, new EcdhKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256))},
            {JweAlgorithm.PBES2_HS256_A128KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128))},
            {JweAlgorithm.PBES2_HS384_A192KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192))},
            {JweAlgorithm.PBES2_HS512_A256KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256))},
            {JweAlgorithm.A128GCMKW, new AesGcmKeyWrapManagement(128)},
            {JweAlgorithm.A192GCMKW, new AesGcmKeyWrapManagement(192)},
            {JweAlgorithm.A256GCMKW, new AesGcmKeyWrapManagement(256)}
        };

        internal static Dictionary<JweCompression, ICompression> CompressionAlgorithms = new Dictionary<JweCompression, ICompression>
        {
            {JweCompression.DEF, new DeflateCompression()}                        
        }; 
        #endregion

        public static JOSE Deserialize(string token, object encryptionKey)
        {
            Ensure.IsNotEmpty(token, "Incoming token expected to be in compact serialization form, not empty, whitespace or null.");
            Ensure.IsNotNull(encryptionKey, "EncryptionKey expected to be not null");

            byte[][] parts = Compact.Parse(token);

            if(parts.Length != 5)
                throw new JoseDeserializationException("Incoming token is not a JWE object.");

            byte[] header = parts[0];
            byte[] encryptedCek = parts[1];
            byte[] iv = parts[2];
            byte[] cipherText = parts[3];
            byte[] signature = parts[4];

            string headerStr = Encoding.UTF8.GetString(header);

            IDictionary<string, object> jweHeader = JSON.Parse<Dictionary<string, object>>(headerStr);
            IKeyManagement keys = KeyAlgorithms[Helper.GetJweAlgorithm((string)jweHeader["alg"])];
            IJweAlgorithm enc = EncryptionAlgorithms[Helper.GetJweEncryption((string)jweHeader["enc"])];
            byte[] cek = keys.Unwrap(encryptedCek, encryptionKey, enc.KeySize, jweHeader);
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));
            byte[] plainText = enc.Decrypt(aad, cek, iv, cipherText, signature);

            if (jweHeader.ContainsKey("zip"))
                plainText = CompressionAlgorithms[Helper.GetJweCompression((string)jweHeader["zip"])].Decompress(plainText);

            string payloadStr = Encoding.UTF8.GetString(plainText);

            return new JOSE(headerStr, payloadStr, signature);
        }

        public JweAlgorithm Algorithm { get; private set; }
        public JweEncryption Encryption { get; private set; }
        public JweCompression Compression { get; private set; }
        public object EncryptionKey { get; private set; }
        public object Payload { get; private set; }
        public IDictionary<string, object> Headers { get; private set; }

        public JWE(JweAlgorithm algorithm, JweEncryption encryption, object encryptionKey, string payload)
            : this(algorithm, encryption, JweCompression.None, encryptionKey, payload)
        { }

        public JWE(JweAlgorithm algorithm, JweEncryption encryption, object encryptionKey, JWE payload)
            : this(algorithm, encryption, JweCompression.None, encryptionKey, payload)
        { }

        public JWE(JweAlgorithm algorithm, JweEncryption encryption, object encryptionKey, JWS payload)
            : this(algorithm, encryption, JweCompression.None, encryptionKey, payload)
        { }

        public JWE(JweAlgorithm algorithm, JweEncryption encryption, JweCompression compression, object encryptionKey, string payload)
            : this(algorithm, encryption, compression, encryptionKey, (object)payload)
        { }

        public JWE(JweAlgorithm algorithm, JweEncryption encryption, JweCompression compression, object encryptionKey, JWE payload)
            : this(algorithm, encryption, compression, encryptionKey, (object)payload)
        { }

        public JWE(JweAlgorithm algorithm, JweEncryption encryption, JweCompression compression, object encryptionKey, JWS payload)
            : this(algorithm, encryption, compression, encryptionKey, (object)payload)
        { }

        private JWE(JweAlgorithm algorithm, JweEncryption encryption, object encryptionKey, object payload)
            : this(algorithm, encryption, JweCompression.None, encryptionKey, payload)
        { }

        private JWE(JweAlgorithm algorithm, JweEncryption encryption, JweCompression compression, object encryptionKey, object payload)
        {
            Ensure.IsNotNull(encryptionKey, "EncryptionKey expected to be not null.");

            if(payload is string)
                Ensure.IsNotEmpty((string)payload, "Payload expected to be not empty, whitespace or null.");
            else
                Ensure.IsNotNull(payload, "Payload expected to be not null.");

            Algorithm = algorithm;
            Encryption = encryption;
            Compression = compression;
            EncryptionKey = encryptionKey;
            Payload = payload;
            Headers = new Dictionary<string, object>();
        }

        public string Serialize()
        {
            IKeyManagement algorithm = KeyAlgorithms[Algorithm];
            IJweAlgorithm encryption = EncryptionAlgorithms[Encryption];

            var jweHeader = new Dictionary<string, object>(Headers);
            jweHeader.Add("alg", Algorithm.GetName());
            jweHeader.Add("enc", Encryption.GetName());

            byte[][] contentKeys = algorithm.WrapNewKey(encryption.KeySize, EncryptionKey, jweHeader);
            byte[] cek = contentKeys[0];
            byte[] encryptedCek = contentKeys[1];

            byte[] plainText = Encoding.UTF8.GetBytes(PayloadToString());

            if (Compression != JweCompression.None)
            {
                jweHeader["zip"] = Compression.GetName();
                plainText = CompressionAlgorithms[Compression].Compress(plainText);
            }

            byte[] header = Encoding.UTF8.GetBytes(JSON.Serialize(jweHeader));
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));
            byte[][] encParts = encryption.Encrypt(aad, plainText, cek);

            return Compact.Serialize(header, encryptedCek, encParts[0], encParts[1], encParts[2]);
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
