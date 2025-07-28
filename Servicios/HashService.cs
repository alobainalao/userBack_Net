using System.Security.Cryptography;
using System.Text;

namespace MyJwtApi.Servicios
{
    public class HashService
    {
        public string Hash(string textoPlano)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(textoPlano);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}
