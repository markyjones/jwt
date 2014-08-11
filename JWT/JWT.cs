using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;

namespace JWTSHA256
{
    public enum JwtHashAlgorithm
    {
        HS256,
        HS384,
        HS512,
        RS256
    }

    /// <summary>
    /// Provides methods for encoding and decoding JSON Web Tokens.
    /// </summary>
    public static class JsonWebToken
    {
        private static readonly Dictionary<JwtHashAlgorithm, Func<object, byte[], byte[]>> SigningAlgorithms;
        private static readonly Dictionary<JwtHashAlgorithm, Action<object, byte[], byte[]>> VerficationAlgorithms;
        private static readonly JavaScriptSerializer JsonSerializer = new JavaScriptSerializer();

        static JsonWebToken()
        {
            SigningAlgorithms = new Dictionary<JwtHashAlgorithm, Func<object, byte[], byte[]>>
            {
                { JwtHashAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256((byte[])key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384((byte[])key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512((byte[])key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.RS256, (rsaProvider, value) => { using (var sha = (RSACryptoServiceProvider)rsaProvider) { return sha.SignData(value, "SHA256"); } } }
            };
            
            VerficationAlgorithms = new Dictionary<JwtHashAlgorithm, Action<object, byte[], byte[]>>
            {
                { JwtHashAlgorithm.HS256, (key, bytesToSign, crypto ) =>  VerfiyHmacToken(key, JwtHashAlgorithm.HS256, bytesToSign,crypto) },
                { JwtHashAlgorithm.HS384, (key,  bytesToSign, crypto ) =>  VerfiyHmacToken(key, JwtHashAlgorithm.HS384, bytesToSign,crypto) },
                { JwtHashAlgorithm.HS512, (key,  bytesToSign, crypto ) =>  VerfiyHmacToken(key, JwtHashAlgorithm.HS512, bytesToSign,crypto) },
                { JwtHashAlgorithm.RS256, (key,  bytesToSign, crypto ) =>  VerfiyRsaToken(key, "SHA256", bytesToSign,crypto) },
            };
        }

        /// <summary>
        /// Creates a JWT given a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON via <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).</param>
        /// <param name="key">The key bytes used to sign the token.</param>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(object payload, byte[] key, JwtHashAlgorithm algorithm)
        {
            return Encode(payload, (object)key, algorithm);
        }

        /// <summary>
        /// Creates a JWT given a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON via <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(object payload, string key, JwtHashAlgorithm algorithm)
        {
            return Encode(payload, Encoding.UTF8.GetBytes(key), algorithm);
        }

        /// <summary>
        /// Creates a JWT given a payload, the certificate to use.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON via <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).</param>
        /// <param name="certificate">The certificate aka pfx used to sign the token.</param>
        /// <returns>The generated JWT.</returns>
        /// /// <exception cref="InvalidOperationException">Thrown if the certificate provided doesn't contain a private key.</exception>
        public static string Encode(object payload, X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException("Certificate requires private key.");
            }
            
            return Encode(payload, certificate.PrivateKey, GetHashAlgorithm(certificate.SignatureAlgorithm));
        }

        /// <summary>
        /// Given a JWT, decode it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="certificate">The certificate (cer) used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>A string containing the JSON payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        public static string Decode(string token, X509Certificate2 certificate, bool verify = true)
        {
            return Decode(token, certificate.PublicKey.Key, verify);
        }

        /// <summary>
        /// Given a JWT, decode it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key bytes that were used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>A string containing the JSON payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        public static string Decode(string token, byte[] key, bool verify = true)
        {
            return Decode(token, (object)key, verify);
        }

        /// <summary>
        /// Given a JWT, decode it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>A string containing the JSON payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        public static string Decode(string token, string key, bool verify = true)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <summary>
        /// Given a JWT, decode it and return the payload as an object (by deserializing it with <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        public static object DecodeToObject(string token, string key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            var payloadData = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
            return payloadData;
        }

        private static string Encode(object payload, object keyOrRsaProvider, JwtHashAlgorithm algorithm)
        {
            var segments = new List<string>();
            var header = new { typ = "JWT", alg = algorithm.ToString() };

            var headerBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header));
            var payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());

            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            byte[] signature = SigningAlgorithms[algorithm](keyOrRsaProvider, bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        private static string Decode(string token, object key, bool verify = true)
        {
            var parts = token.Split('.');
            var header = parts[0];
            var payload = parts[1];
            var crypto = Base64UrlDecode(parts[2]);

            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            var headerData = JsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));

            if (!verify)
            {
                return payloadJson;
            }

            var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
            var algorithm = (string)headerData["alg"];

            VerficationAlgorithms[GetHashAlgorithm(algorithm)](key, bytesToSign, crypto);

            return payloadJson;
        }

        private static void VerfiyHmacToken(object key, JwtHashAlgorithm algorithm, byte[] bytesToSign, byte[] crypto)
        {
            var signature = SigningAlgorithms[algorithm](key, bytesToSign);

            var decodedCrypto = Convert.ToBase64String(crypto);
            var decodedSignature = Convert.ToBase64String(signature);

            if (decodedCrypto != decodedSignature)
            {
                throw new SignatureVerificationException(string.Format("Invalid signature. Expected {0} got {1}", decodedCrypto,
                    decodedSignature));
            }
        }

        private static void VerfiyRsaToken(object publicKey, string algorithm, byte[] bytesToSign, byte[] crypto)
        {
            using (var sha = ((RSACryptoServiceProvider)publicKey))
            {
                if (!sha.VerifyData(bytesToSign, algorithm, crypto))
                {
                    throw new SignatureVerificationException("Invalid signature.");
                }
            }
        }

        private static JwtHashAlgorithm GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "HS256": return JwtHashAlgorithm.HS256;
                case "HS384": return JwtHashAlgorithm.HS384;
                case "HS512": return JwtHashAlgorithm.HS512;
                case "RS256": return JwtHashAlgorithm.RS256;
                default: throw new SignatureVerificationException("Algorithm not supported.");
            }
        }

        private static JwtHashAlgorithm GetHashAlgorithm(Oid algorithm)
        {
            switch (algorithm.Value)
            {
                case "1.2.840.113549.1.1.11": return JwtHashAlgorithm.RS256;
                default: throw new SignatureVerificationException("Algorithm not supported.");
            }
        }

        // from JWT spec

        public static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        // from JWT spec

        public static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }

    public class SignatureVerificationException : Exception
    {
        public SignatureVerificationException(string message)
            : base(message)
        {
        }
    }
}
