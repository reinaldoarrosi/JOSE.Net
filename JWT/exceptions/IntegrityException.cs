using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JOSE.Net.Exceptions
{
    public class IntegrityException : JoseException
    {
        public IntegrityException(string message) : base(message) { }
        public IntegrityException(string message, Exception innerException) : base(message, innerException) { }
    }
}
