using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jose
{
    public class JSON
    {
        private static IJsonMapper _serializer;

        static JSON()
        {
            Configure(new JSONNetOrJSSerializerMapper());
        }

        public static void Configure(IJsonMapper serializer)
        {
            Ensure.IsNotNull(serializer, "Incoming serializes expected to be not null");
            _serializer = serializer;
        }

        public static string Serialize(object obj)
        {
            return _serializer.Serialize(obj);
        }

        public static T Parse<T>(string json)
        {
            return _serializer.Parse<T>(json);
        }
    }
}
