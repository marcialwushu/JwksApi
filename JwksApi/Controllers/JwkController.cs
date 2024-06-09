using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JwksApi.Models;
using System.Text.RegularExpressions;

namespace JwksApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class JwkController : ControllerBase
    {
        private JwkKey GenerateJwkFromPfx(string pfxPath, string password)
        {
            using var certificate = new X509Certificate2(pfxPath, password, X509KeyStorageFlags.Exportable);
            using var rsa = certificate.GetRSAPublicKey();
            var parameters = rsa.ExportParameters(false);
            var modulus = Convert.ToBase64String(parameters.Modulus);
            var exponent = Convert.ToBase64String(parameters.Exponent);

            var x5c = new[] { Convert.ToBase64String(certificate.RawData) };
            var thumbprint = Convert.ToBase64String(certificate.GetCertHash());

            return new JwkKey
            {
                KeyType = "RSA",
                Use = "sig",
                KeyId = certificate.Thumbprint,
                Modulus = modulus,
                Exponent = exponent,
                X5c = x5c,
                X5t = thumbprint
            };
        }

        [HttpGet("jwks.json")]
        public IActionResult GetJwk()
        {
            var jwk = GenerateJwkFromPfx("C:/Users/marci/source/repos/service/AuthSampleCode/GenerateJwt/jwt.sample.code.pfx", "123456");
            var json = JsonConvert.SerializeObject(jwk);
            return Ok(json);
        }
    }
}
