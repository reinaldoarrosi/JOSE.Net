using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JOSE.Net
{
    public class JOSEObject
    {
        public string Header { get; private set; }
        public string Payload { get; private set; }
        public byte[] Signature { get; private set; }

        public JOSEObject(string header, string payload, byte[] signature = null)
        {
            Ensure.IsNotEmpty(header, "Incoming header expected to be not empty, whitespace or null.");

            Header = header;
            Payload = payload ?? string.Empty;
            Signature = signature ?? new byte[0];
        }

        public string SignatureBase64 { get { return Base64Url.Encode(Signature); } }
    }
}
