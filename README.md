# JSON Web Token (JWT) Implementation for .NET

This library supports generating and decoding [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10).

## Installation
The easiest way to install is via NuGet.  See [here](https://nuget.org/packages/JWT).  Else, you can download and compile it yourself.

## Usage
### Creating Tokens
    var payload = new Dictionary<string, object>() {
        { "claim1", 0 },
        { "claim2", "claim2-value" }
    };
    var secretKey = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
    string token = JWT.JsonWebToken.Encode(payload, secretKey, JWT.JwtHashAlgorithm.HS256);
    Console.Out.WriteLine(token);

Output will be:

    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s

Or

    var payload = new Dictionary<string, object>() {
        { "claim1", 0 },
        { "claim2", "claim2-value" }
    };
    var cert = new X509Certificate2("test.pfx");
    string token = JWT.JsonWebToken.Encode(payload, cert);
    Console.Out.WriteLine(token);

### Verifying and Decoding Tokens

    var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
    var secretKey = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
    try
    {
        string jsonPayload = JWT.JsonWebToken.Decode(token, secretKey);
        Console.Out.WriteLine(jsonPayload);
    }
    catch (JWT.SignatureVerificationException)
    {
        Console.Out.WriteLine("Invalid token!");
    }

Output will be:

    {"claim1":0,"claim2":"claim2-value"}

Or

    var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
    var cert = new X509Certificate2("test.crt");               
    try
    {
        string jsonPayload = JWT.JsonWebToken.Decode(token, cert);
        Console.Out.WriteLine(jsonPayload);
    }
    catch (JWT.SignatureVerificationException)
    {
        Console.Out.WriteLine("Invalid token!");
    }

You can also deserialize the JSON payload directly to a .Net object with DecodeToObject:

    var payload = JWT.JsonWebToken.DecodeToObject(token, secretKey) as IDictionary<string, object>;
    Console.Out.WriteLine(payload["claim2"]);

which will output:
    
    claim2-value

### Creating a JWT for the Salesforce OAuth 2.0 JWT Bearer Token Flow

    var payload = new Dictionary<string, object>() {
        { "iss", "3MVG9A2kN3Bn1...(Your Client Id)..." },
        { "prn", "example@user.com" },
        { "aud", "https://login.salesforce.com" },
        { "exp", DateTime.UtcNow.Subtract(new DateTime(1970,1,1,0,0,0)).TotalSeconds }
    };

    var cert = new X509Certificate2("test.pfx");
    string token = JWT.JsonWebToken.Encode(payload, cert);
    Console.Out.WriteLine(token);