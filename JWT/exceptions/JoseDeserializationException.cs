using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jose.exceptions
{
    public class JoseDeserializationException : JoseException
    {
        public JoseDeserializationException(string message) : base(message) { }
        public JoseDeserializationException(string message, Exception innerException) : base(message, innerException) { }
    }
}
