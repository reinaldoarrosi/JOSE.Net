namespace JOSE.Net
{
    public interface ICompression
    {
        byte[] Compress(byte[] plainText);
        byte[] Decompress(byte[] compressedText);
    }
}