using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jose.exceptions
{
    public class EncryptionException : JoseException
    {
        public EncryptionException(string message) : base(message) { }
        public EncryptionException(string message, Exception innerException) : base(message, innerException) { }
    }
}
