using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JOSE.Net.Exceptions
{
    public class JoseException : Exception
    {
        public JoseException(string message) : base(message) { }
        public JoseException(string message, Exception innerException) : base(message, innerException) { }
    }
}
