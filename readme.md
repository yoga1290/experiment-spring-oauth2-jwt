# What's this?
Playing around with OAuth sample; forked from [spring-guides/tut-spring-security-and-angular-js](https://github.com/spring-guides/tut-spring-security-and-angular-js)
Check the [Spring's Guide/Tutorial](https://spring.io/guides/tutorials/spring-security-and-angular-js/)

# Install & Run:

```BASH
git clone https://github.com/yoga1290/tut-spring-security-and-angular-js.git;

cd tut-spring-security-and-angular-js/oauth2/authserver;

mvn spring-boot:run;
```

-------------------------------------------------
# Notes

## Breaking Down a JSON Web Token

### Overview:

**Header**, **Payload** & **signature** as base-64 encoded string:
![JWT](https://cask.scotch.io/2014/11/json-web-token-overview1.png)

+	Header
	+	**alg**: algorithm used for signature encryption; none | HS256| RS256
	+	[**typ**](https://tools.ietf.org/html/rfc7519#section-5.1): media type
+	Payload
	+	iss: The issuer of the token
	+	sub: The subject of the token
	+  aud: The audience of the token
	+	**exp**: This will probably be the registered claim most often used. This will define the expiration in NumericDate value. The expiration MUST be after the current date/time.
	+	nbf: Defines the time before which the JWT MUST NOT be accepted for processing
	+	iat: The time the JWT was issued. Can be used to determine the age of the JWT
	+	**jti**: Unique identifier for the JWT. Can be used to prevent the JWT from being replayed. This is helpful for a one time use token.
+	signature
The signature is calculated by base64url encoding the header and payload and concatenating them with a period as a separator:
```
key = 'secretkey'
unsignedToken = encodeBase64(header) + '.' + encodeBase64(payload)
signature = HMAC-SHA256(key, unsignedToken)
```

### RSA or HMAC?:
+ Tokens are created and **signed using a private key**, but **verified using a corresponding public key**
+ In **HMAC** signatures, the `verification key = signing key`; an attacker can abuse this (in case of client-side verification)


## Enable @Secured
We can enable annotation-based security using the `@EnableGlobalMethodSecurity` annotation on any `@Configuration` instance. Check [Spring Security](http://docs.spring.io/spring-security/site/docs/4.1.1.RELEASE/reference/htmlsingle/#enableglobalmethodsecurity)!


## Try it out:
You can try [RO Password Credentials](https://tools.ietf.org/html/rfc6749#section-1.3.3) flow to generate JWT token:
```
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://localhost:9999/uaa/oauth/token");
xhr.setRequestHeader("authorization", "Basic " + btoa('acme:acmesecret'));
xhr.setRequestHeader("content-type", "application/x-www-form-urlencoded");
xhr.send("grant_type=password&client_id=acme&scope=openid&username=user&password=password&client_secret=acmesecret");
```
You can try to decode the header & payload of the JWT token:
```
'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NzAxOTA3NjksInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJ3cml0ZSIsInJlYWQiXSwianRpIjoiMTRlNGQyYzItZmZmOC00YWNmLWE3NzktNzRkMDY0MTk5YTk1IiwiY2xpZW50X2lkIjoiYWNtZSIsInNjb3BlIjpbIm9wZW5pZCJdfQ.eb1OY2FYonzcoBmfRtIcVLIR_YWvlnPvzGkfmStBKJJdKCNcwu6X4-mwqQlyMejSIGpIYpHADrBt6Ip9WIKlca2ewAM3b5TK5okSCWuTKEPmpwhOhxBlhwOzRwoB727AQjlhwb9QA14I68Pdg8_xm_l8AS2v4fiMosb0N7vvo8yZhrHVl2zsC6Kgd5IAh9Z-BwluOhPWMKPNntYQ4MpbdrDbPs7u8wRS9_MOAVWL3A3LN2rFWbRxKUxM5PdssfeDDxfXV7ioYTGJFcoPcHnJT9j_c0oq15yuTGvepwiKF2kRsW58JixbTb0ZwxX0eHSKTb7UfpHiR7UA6YF40WdsFw'
.split('.')
.map(function(str, index) {
	if(index<2) {
		return JSON.parse(atob(str));
	} else {
		return str;
	}
});

// OUTPUT:
{"alg":"RS256", "typ":"JWT"}

{"exp":1470190769,
"user_name":"user",
"authorities":["write","read"],
"jti":"14e4d2c2-fff8-4acf-a779-74d064199a95",
"client_id":"acme",
"scope":["openid"]}

// ... signature
```


## Ref & Resources
+ [RFC#7519 | JWT](https://tools.ietf.org/html/rfc7519)
+ [Scotch | The Anatomy of a JSON Web Token](https://scotch.io/tutorials/the-anatomy-of-a-json-web-token)
+ [Auth0 | Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
+ [mozilla | Base64 To ASCII](https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding)
+ [Baeldung | Generating RSA Keys](http://www.baeldung.com/spring-security-oauth-jwt)
+ [Critical vulnerabilities in JSON Web Token libraries](https://www.chosenplaintext.ca/2015/03/31/jwt-algorithm-confusion.html)
+ [Spring Security | EnableGlobalMethodSecurity]([reference](http://docs.spring.io/spring-security/site/docs/4.1.1.RELEASE/reference/htmlsingle/#enableglobalmethodsecurity))