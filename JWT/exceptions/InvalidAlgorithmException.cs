using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JOSE.Net.Exceptions
{
    public class InvalidAlgorithmException : JoseException
    {
        public InvalidAlgorithmException(string message) : base(message) { }
        public InvalidAlgorithmException(string message, Exception innerException) : base(message, innerException) { }
    }
}
