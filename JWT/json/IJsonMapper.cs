namespace JOSE.Net
{
    public interface IJsonMapper
    {
        string Serialize(object obj);
        T Parse<T>(string json);
    }
}