using System;
using System.IO;
using System.Web.Script.Serialization;

namespace Jose
{
    public class JSONNetOrJSSerializerMapper : IJsonMapper
    {
        private JavaScriptSerializer js;
        private dynamic jsonNet;

        public JSONNetOrJSSerializerMapper()
        {
            try
            {
                Type jsonNetSerializerType = Type.GetType("Newtonsoft.Json.JsonSerializer");

                if (jsonNetSerializerType != null)
                    jsonNet = Activator.CreateInstance(jsonNetSerializerType);
                else
                    js = new JavaScriptSerializer();
            }
            catch
            {
                jsonNet = null;
                js = new JavaScriptSerializer();
            }
        }


        public string Serialize(object obj)
        {
            if (jsonNet != null)
            {
                using (TextWriter writer = new StringWriter())
                {
                    jsonNet.Serialize(writer, obj, obj.GetType());
                    writer.Flush();

                    return writer.ToString();
                }
            }
            else
            {
                return js.Serialize(obj);
            }
        }

        public T Parse<T>(string json)
        {
            if (jsonNet != null)
            {
                using (TextReader reader = new StringReader(json))
                {
                    return (T)jsonNet.Deserialize(reader, typeof(T));
                }
            }
            else
            {
                return js.Deserialize<T>(json);
            }
        }
    }
}