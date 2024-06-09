﻿using Newtonsoft.Json;

namespace JwksApi.Models
{
    public class JwkKey
    {
        [JsonProperty("kty")]
        public string KeyType { get; set; }

        [JsonProperty("use")]
        public string Use { get; set; }

        [JsonProperty("kid")]
        public string KeyId { get; set; }

        [JsonProperty("n")]
        public string Modulus { get; set; }

        [JsonProperty("e")]
        public string Exponent { get; set; }

        [JsonProperty("x5c")]
        public string[] X5c { get; set; }

        [JsonProperty("x5t")]
        public string X5t { get; set; }
    }
}
