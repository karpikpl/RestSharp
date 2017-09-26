using System;
using System.Collections.Generic;
using System.Linq;
#if !WINDOWS_UWP
using System.Security.Cryptography;
#else
using Windows.Security.Cryptography.Core;
#endif
using System.Text;
using RestSharp.Authenticators.OAuth.Extensions;
using System.Runtime.Serialization;
using System.IO;
using System.Diagnostics;

namespace RestSharp.Authenticators.OAuth
{
#if !SILVERLIGHT && !WINDOWS_PHONE && !WINDOWS_UWP
	[Serializable]
#endif
#if WINDOWS_UWP
    [DataContract]
#endif
	internal static class OAuthTools
	{
		private const string ALPHA_NUMERIC = UPPER + LOWER + DIGIT;

		private const string DIGIT = "1234567890";

		private const string LOWER = "abcdefghijklmnopqrstuvwxyz";

		private const string UNRESERVED = ALPHA_NUMERIC + "-._~";

		private const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

		private static readonly Random random;

		private static readonly object randomLock = new object();

#if !SILVERLIGHT && !WINDOWS_PHONE && !WINDOWS_UWP
		private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
#endif

		static OAuthTools()
		{
#if !SILVERLIGHT && !WINDOWS_PHONE && !WINDOWS_UWP
			byte[] bytes = new byte[4];

			rng.GetNonZeroBytes(bytes);
			random = new Random(BitConverter.ToInt32(bytes, 0));
#else
            random = new Random();
#endif
		}

		/// <summary>
		/// All text parameters are UTF-8 encoded (per section 5.1).
		/// </summary>
		/// <seealso cref="http://www.hueniverse.com/hueniverse/2008/10/beginners-gui-1.html"/> 
		private static readonly Encoding encoding = Encoding.UTF8;

		/// <summary>
		/// Generates a random 16-byte lowercase alphanumeric string. 
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#nonce"/>
		/// <returns></returns>
		public static string GetNonce()
		{
			const string chars = (LOWER + DIGIT);

			char[] nonce = new char[16];

			lock (randomLock)
			{
				for (int i = 0; i < nonce.Length; i++)
				{
					nonce[i] = chars[random.Next(0, chars.Length)];
				}
			}

			return new string(nonce);
		}

		/// <summary>
		/// Generates a timestamp based on the current elapsed seconds since '01/01/1970 0000 GMT"
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#nonce"/>
		/// <returns></returns>
		public static string GetTimestamp()
		{
			return GetTimestamp(DateTime.UtcNow);
		}

		/// <summary>
		/// Generates a timestamp based on the elapsed seconds of a given time since '01/01/1970 0000 GMT"
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#nonce"/>
		/// <param name="dateTime">A specified point in time.</param>
		/// <returns></returns>
		public static string GetTimestamp(DateTime dateTime)
		{
			long timestamp = dateTime.ToUnixTime();

			return timestamp.ToString();
		}

		/// <summary>
		/// The set of characters that are unreserved in RFC 2396 but are NOT unreserved in RFC 3986.
		/// </summary>
		/// <seealso cref="http://stackoverflow.com/questions/846487/how-to-get-uri-escapedatastring-to-comply-with-rfc-3986" />
		private static readonly string[] uriRfc3986CharsToEscape = { "!", "*", "'", "(", ")" };

		private static readonly string[] uriRfc3968EscapedHex = { "%21", "%2A", "%27", "%28", "%29" };

		/// <summary>
		/// URL encodes a string based on section 5.1 of the OAuth spec.
		/// Namely, percent encoding with [RFC3986], avoiding unreserved characters,
		/// upper-casing hexadecimal characters, and UTF-8 encoding for text value pairs.
		/// </summary>
		/// <param name="value">The value to escape.</param>
		/// <returns>The escaped value.</returns>
		/// <remarks>
		/// The <see cref="Uri.EscapeDataString"/> method is <i>supposed</i> to take on
		/// RFC 3986 behavior if certain elements are present in a .config file.  Even if this
		/// actually worked (which in my experiments it <i>doesn't</i>), we can't rely on every
		/// host actually having this configuration element present.
		/// </remarks>
		/// <seealso cref="http://oauth.net/core/1.0#encoding_parameters" />
		/// <seealso cref="http://stackoverflow.com/questions/846487/how-to-get-uri-escapedatastring-to-comply-with-rfc-3986" />
		public static string UrlEncodeRelaxed(string value)
		{
			// Start with RFC 2396 escaping by calling the .NET method to do the work.
			// This MAY sometimes exhibit RFC 3986 behavior (according to the documentation).
			// If it does, the escaping we do that follows it will be a no-op since the
			// characters we search for to replace can't possibly exist in the string.
			StringBuilder escaped = new StringBuilder(Uri.EscapeDataString(value));

			// Upgrade the escaping to RFC 3986, if necessary.
			for (int i = 0; i < uriRfc3986CharsToEscape.Length; i++)
			{
				string t = uriRfc3986CharsToEscape[i];

				escaped.Replace(t, uriRfc3968EscapedHex[i]);
			}

			// Return the fully-RFC3986-escaped string.
			return escaped.ToString();
		}

		/// <summary>
		/// URL encodes a string based on section 5.1 of the OAuth spec.
		/// Namely, percent encoding with [RFC3986], avoiding unreserved characters,
		/// upper-casing hexadecimal characters, and UTF-8 encoding for text value pairs.
		/// </summary>
		/// <param name="value"></param>
		/// <seealso cref="http://oauth.net/core/1.0#encoding_parameters" />
		public static string UrlEncodeStrict(string value)
		{
			// From oauth spec above: -
			// Characters not in the unreserved character set ([RFC3986]
			// (Berners-Lee, T., "Uniform Resource Identifiers (URI):
			// Generic Syntax," .) section 2.3) MUST be encoded.
			// ...
			// unreserved = ALPHA, DIGIT, '-', '.', '_', '~'
			string result = "";

			value.ForEach(c =>
						  {
							  result += UNRESERVED.Contains(c)
								  ? c.ToString()
								  : c.ToString()
									 .PercentEncode();
						  });

			return result;
		}

		/// <summary>
		/// Sorts a collection of key-value pairs by name, and then value if equal,
		/// concatenating them into a single string. This string should be encoded
		/// prior to, or after normalization is run.
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#rfc.section.9.1.1"/>
		/// <param name="parameters"></param>
		/// <returns></returns>
		public static string NormalizeRequestParameters(WebParameterCollection parameters)
		{
			WebParameterCollection copy = SortParametersExcludingSignature(parameters);
			string concatenated = copy.Concatenate("=", "&");

			return concatenated;
		}

		/// <summary>
		/// Sorts a <see cref="WebParameterCollection"/> by name, and then value if equal.
		/// </summary>
		/// <param name="parameters">A collection of parameters to sort</param>
		/// <returns>A sorted parameter collection</returns>
		public static WebParameterCollection SortParametersExcludingSignature(WebParameterCollection parameters)
		{
			WebParameterCollection copy = new WebParameterCollection(parameters);
			IEnumerable<WebPair> exclusions = copy.Where(n => n.Name.EqualsIgnoreCase("oauth_signature"));

			copy.RemoveAll(exclusions);
			copy.ForEach(p =>
						 {
							 p.Name = UrlEncodeStrict(p.Name);
							 p.Value = UrlEncodeStrict(p.Value);
						 });
			copy.Sort((x, y) => string.CompareOrdinal(x.Name, y.Name) != 0
				? string.CompareOrdinal(x.Name, y.Name)
				: string.CompareOrdinal(x.Value, y.Value));

			return copy;
		}

		/// <summary>
		/// Creates a request URL suitable for making OAuth requests.
		/// Resulting URLs must exclude port 80 or port 443 when accompanied by HTTP and HTTPS, respectively.
		/// Resulting URLs must be lower case.
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#rfc.section.9.1.2"/>
		/// <param name="url">The original request URL</param>
		/// <returns></returns>
		public static string ConstructRequestUrl(Uri url)
		{
			if (url == null)
			{
				throw new ArgumentNullException("url");
			}

			StringBuilder sb = new StringBuilder();
			string requestUrl = "{0}://{1}".FormatWith(url.Scheme, url.Host);
			string qualified = ":{0}".FormatWith(url.Port);
			bool basic = url.Scheme == "http" && url.Port == 80;
			bool secure = url.Scheme == "https" && url.Port == 443;

			sb.Append(requestUrl);
			sb.Append(!basic && !secure
				? qualified
				: "");
			sb.Append(url.AbsolutePath);

			return sb.ToString(); //.ToLower();
		}

		/// <summary>
		/// Creates a request elements concatentation value to send with a request. 
		/// This is also known as the signature base.
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#rfc.section.9.1.3"/>
		/// <seealso cref="http://oauth.net/core/1.0#sig_base_example"/>
		/// <param name="method">The request's HTTP method type</param>
		/// <param name="url">The request URL</param>
		/// <param name="parameters">The request's parameters</param>
		/// <returns>A signature base string</returns>
		public static string ConcatenateRequestElements(string method, string url, WebParameterCollection parameters)
		{
			StringBuilder sb = new StringBuilder();

			// Separating &'s are not URL encoded
			string requestMethod = method.ToUpper().Then("&");
			string requestUrl = UrlEncodeRelaxed(ConstructRequestUrl(url.AsUri())).Then("&");
			string requestParameters = UrlEncodeRelaxed(NormalizeRequestParameters(parameters));

			sb.Append(requestMethod);
			sb.Append(requestUrl);
			sb.Append(requestParameters);

			return sb.ToString();
		}

		/// <summary>
		/// Creates a signature value given a signature base and the consumer secret.
		/// This method is used when the token secret is currently unknown.
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#rfc.section.9.2"/>
		/// <param name="signatureMethod">The hashing method</param>
		/// <param name="signatureBase">The signature base</param>
		/// <param name="consumerSecret">The consumer key</param>
		/// <returns></returns>
		public static string GetSignature(OAuthSignatureMethod signatureMethod, string signatureBase, string consumerSecret)
		{
			return GetSignature(signatureMethod, OAuthSignatureTreatment.Escaped, signatureBase, consumerSecret, null);
		}

		/// <summary>
		/// Creates a signature value given a signature base and the consumer secret.
		/// This method is used when the token secret is currently unknown.
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#rfc.section.9.2"/>
		/// <param name="signatureMethod">The hashing method</param>
		/// <param name="signatureTreatment">The treatment to use on a signature value</param>
		/// <param name="signatureBase">The signature base</param>
		/// <param name="consumerSecret">The consumer key</param>
		/// <returns></returns>
		public static string GetSignature(OAuthSignatureMethod signatureMethod, OAuthSignatureTreatment signatureTreatment,
			string signatureBase, string consumerSecret)
		{
			return GetSignature(signatureMethod, signatureTreatment, signatureBase, consumerSecret, null);
		}

		/// <summary>
		/// Creates a signature value given a signature base and the consumer secret and a known token secret.
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#rfc.section.9.2"/>
		/// <param name="signatureMethod">The hashing method</param>
		/// <param name="signatureBase">The signature base</param>
		/// <param name="consumerSecret">The consumer secret</param>
		/// <param name="tokenSecret">The token secret</param>
		/// <returns></returns>
		public static string GetSignature(OAuthSignatureMethod signatureMethod, string signatureBase, string consumerSecret,
			string tokenSecret)
		{
			return GetSignature(signatureMethod, OAuthSignatureTreatment.Escaped, consumerSecret, tokenSecret);
		}

		/// <summary>
		/// Creates a signature value given a signature base and the consumer secret and a known token secret.
		/// </summary>
		/// <seealso cref="http://oauth.net/core/1.0#rfc.section.9.2"/>
		/// <param name="signatureMethod">The hashing method</param>
		/// <param name="signatureTreatment">The treatment to use on a signature value</param>
		/// <param name="signatureBase">The signature base</param>
		/// <param name="consumerSecret">The consumer secret</param>
		/// <param name="tokenSecret">The token secret</param>
		/// <returns></returns>
		public static string GetSignature(OAuthSignatureMethod signatureMethod, OAuthSignatureTreatment signatureTreatment,
			string signatureBase, string consumerSecret, string tokenSecret)
		{
			if (tokenSecret.IsNullOrBlank())
			{
				tokenSecret = string.Empty;
			}

			var unencodedConsumerSecret = consumerSecret;
			consumerSecret = UrlEncodeRelaxed(consumerSecret);
			tokenSecret = UrlEncodeRelaxed(tokenSecret);

			string signature;

			switch (signatureMethod)
			{
				case OAuthSignatureMethod.HmacSha1:
					{
#if !WINDOWS_UWP
						HMACSHA1 crypto = new HMACSHA1();
						string key = "{0}&{1}".FormatWith(consumerSecret, tokenSecret);

						crypto.Key = encoding.GetBytes(key);
						signature = signatureBase.HashWith(crypto);
#else
                    signature = signatureBase.HashWith(HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1));         
#endif
						break;
					}

				case OAuthSignatureMethod.HmacSha256:
					{
						HMACSHA256 crypto = new HMACSHA256();
						string key = "{0}&{1}".FormatWith(consumerSecret, tokenSecret);

						crypto.Key = encoding.GetBytes(key);
						signature = signatureBase.HashWith(crypto);

						break;
					}

				case OAuthSignatureMethod.RsaSha1:
					{
						//using (var provider = new RSACryptoServiceProvider() { PersistKeyInCsp = false })
						using (var provider = Crypto.DecodeRsaPrivateKey(Convert.FromBase64String(unencodedConsumerSecret.Replace("\n", string.Empty))))
						{
							//provider.FromXmlString(unencodedConsumerSecret);

							SHA1Managed hasher = new SHA1Managed();
							byte[] hash = hasher.ComputeHash(encoding.GetBytes(signatureBase));

							signature = Convert.ToBase64String(provider.SignHash(hash, CryptoConfig.MapNameToOID("SHA1")));
						}
						break;
					}

				case OAuthSignatureMethod.PlainText:
					{
						signature = "{0}&{1}".FormatWith(consumerSecret, tokenSecret);

						break;
					}

				default:
					throw new NotImplementedException("Only HMAC-SHA1, HMAC-SHA256, and RSA-SHA1 are currently supported.");
			}

			string result = signatureTreatment == OAuthSignatureTreatment.Escaped
				? UrlEncodeRelaxed(signature)
				: signature;

			return result;
		}
	}

	public static class Crypto
	{
		/// <summary>
		/// This helper function parses an RSA private key using the ASN.1 format
		/// </summary>
		/// <param name="privateKeyBytes">Byte array containing PEM string of private key.</param>
		/// <returns>An instance of <see cref="RSACryptoServiceProvider"/> rapresenting the requested private key.
		/// Null if method fails on retriving the key.</returns>
		public static RSACryptoServiceProvider DecodeRsaPrivateKey(byte[] privateKeyBytes)
		{
			MemoryStream ms = new MemoryStream(privateKeyBytes);
			BinaryReader rd = new BinaryReader(ms);

			try
			{
				byte byteValue;
				ushort shortValue;

				shortValue = rd.ReadUInt16();

				switch (shortValue)
				{
					case 0x8130:
						// If true, data is little endian since the proper logical seq is 0x30 0x81
						rd.ReadByte(); //advance 1 byte
						break;
					case 0x8230:
						rd.ReadInt16();  //advance 2 bytes
						break;
					default:
						Debug.Assert(false);     // Improper ASN.1 format
						return null;
				}

				shortValue = rd.ReadUInt16();
				if (shortValue != 0x0102) // (version number)
				{
					Debug.Assert(false);     // Improper ASN.1 format, unexpected version number
					return null;
				}

				byteValue = rd.ReadByte();
				if (byteValue != 0x00)
				{
					Debug.Assert(false);     // Improper ASN.1 format
					return null;
				}

				// The data following the version will be the ASN.1 data itself, which in our case
				// are a sequence of integers.

				// In order to solve a problem with instancing RSACryptoServiceProvider
				// via default constructor on .net 4.0 this is a hack
				CspParameters parms = new CspParameters();
				// https://blogs.msdn.microsoft.com/winsdk/2009/11/16/opps-system-security-cryptography-cryptographicexception-the-system-cannot-find-the-file-specified/

				if (System.Configuration.ConfigurationManager.AppSettings["Environment"] == "Azure")
				{
					parms.Flags = CspProviderFlags.UseMachineKeyStore;
				}
				else
				{
					parms.Flags = CspProviderFlags.NoFlags;
				}
				parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
				parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;

				RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms) { PersistKeyInCsp = false };
				RSAParameters rsAparams = new RSAParameters();

				rsAparams.Modulus = rd.ReadBytes(Helpers.DecodeIntegerSize(rd));

				// Argh, this is a pain.  From emperical testing it appears to be that RSAParameters doesn't like byte buffers that
				// have their leading zeros removed.  The RFC doesn't address this area that I can see, so it's hard to say that this
				// is a bug, but it sure would be helpful if it allowed that. So, there's some extra code here that knows what the
				// sizes of the various components are supposed to be.  Using these sizes we can ensure the buffer sizes are exactly
				// what the RSAParameters expect.  Thanks, Microsoft.
				RSAParameterTraits traits = new RSAParameterTraits(rsAparams.Modulus.Length * 8);

				rsAparams.Modulus = Helpers.AlignBytes(rsAparams.Modulus, traits.size_Mod);
				rsAparams.Exponent = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Exp);
				rsAparams.D = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_D);
				rsAparams.P = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_P);
				rsAparams.Q = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Q);
				rsAparams.DP = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DP);
				rsAparams.DQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DQ);
				rsAparams.InverseQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_InvQ);

				rsa.ImportParameters(rsAparams);
				return rsa;
			}
			catch (Exception)
			{
				throw;
			}
			finally
			{
				rd.Close();
			}
		}
	}

	public static class Helpers
	{
		/// <summary>
		/// This helper function parses an integer size from the reader using the ASN.1 format
		/// </summary>
		/// <param name="rd"></param>
		/// <returns></returns>
		public static int DecodeIntegerSize(System.IO.BinaryReader rd)
		{
			byte byteValue;
			int count;

			byteValue = rd.ReadByte();
			if (byteValue != 0x02)        // indicates an ASN.1 integer value follows
				return 0;

			byteValue = rd.ReadByte();
			if (byteValue == 0x81)
			{
				count = rd.ReadByte();    // data size is the following byte
			}
			else if (byteValue == 0x82)
			{
				byte hi = rd.ReadByte();  // data size in next 2 bytes
				byte lo = rd.ReadByte();
				count = BitConverter.ToUInt16(new[] { lo, hi }, 0);
			}
			else
			{
				count = byteValue;        // we already have the data size
			}

			//remove high order zeros in data
			while (rd.ReadByte() == 0x00)
			{
				count -= 1;
			}
			rd.BaseStream.Seek(-1, System.IO.SeekOrigin.Current);

			return count;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="pemString"></param>
		/// <param name="type"></param>
		/// <returns></returns>
		public static byte[] GetBytesFromPEM(string pemString, PemStringType type)
		{
			string header; string footer;

			switch (type)
			{
				case PemStringType.Certificate:
					header = "-----BEGIN CERTIFICATE-----";
					footer = "-----END CERTIFICATE-----";
					break;
				case PemStringType.RsaPrivateKey:
					header = "-----BEGIN RSA PRIVATE KEY-----";
					footer = "-----END RSA PRIVATE KEY-----";
					break;
				default:
					return null;
			}

			int start = pemString.IndexOf(header, StringComparison.Ordinal) + header.Length;
			int end = pemString.IndexOf(footer, start, StringComparison.Ordinal) - start;
			return Convert.FromBase64String(pemString.Substring(start, end));
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="inputBytes"></param>
		/// <param name="alignSize"></param>
		/// <returns></returns>
		public static byte[] AlignBytes(byte[] inputBytes, int alignSize)
		{
			int inputBytesSize = inputBytes.Length;

			if ((alignSize != -1) && (inputBytesSize < alignSize))
			{
				byte[] buf = new byte[alignSize];
				for (int i = 0; i < inputBytesSize; ++i)
				{
					buf[i + (alignSize - inputBytesSize)] = inputBytes[i];
				}
				return buf;
			}
			else
			{
				return inputBytes;      // Already aligned, or doesn't need alignment
			}
		}
	}

	public enum PemStringType
	{
		Certificate,
		RsaPrivateKey
	}

	class RSAParameterTraits
	{
		public RSAParameterTraits(int modulusLengthInBits)
		{
			// The modulus length is supposed to be one of the common lengths, which is the commonly referred to strength of the key,
			// like 1024 bit, 2048 bit, etc.  It might be a few bits off though, since if the modulus has leading zeros it could show
			// up as 1016 bits or something like that.
			int assumedLength = -1;
			double logbase = Math.Log(modulusLengthInBits, 2);
			if (Math.Abs(logbase - (int)logbase) < 0.00001)
			{
				// It's already an even power of 2
				assumedLength = modulusLengthInBits;
			}
			else
			{
				// It's not an even power of 2, so round it up to the nearest power of 2.
				assumedLength = (int)(logbase + 1.0);
				assumedLength = (int)(Math.Pow(2, assumedLength));
				System.Diagnostics.Debug.Assert(false);  // Can this really happen in the field?  I've never seen it, so if it happens
									 // you should verify that this really does the 'right' thing!
			}

			switch (assumedLength)
			{
				case 1024:
					size_Mod = 0x80;
					size_Exp = -1;
					size_D = 0x80;
					size_P = 0x40;
					size_Q = 0x40;
					size_DP = 0x40;
					size_DQ = 0x40;
					size_InvQ = 0x40;
					break;
				case 2048:
					size_Mod = 0x100;
					size_Exp = -1;
					size_D = 0x100;
					size_P = 0x80;
					size_Q = 0x80;
					size_DP = 0x80;
					size_DQ = 0x80;
					size_InvQ = 0x80;
					break;
				case 4096:
					size_Mod = 0x200;
					size_Exp = -1;
					size_D = 0x200;
					size_P = 0x100;
					size_Q = 0x100;
					size_DP = 0x100;
					size_DQ = 0x100;
					size_InvQ = 0x100;
					break;
				default:
					System.Diagnostics.Debug.Assert(false); // Unknown key size?
					break;
			}
		}

		public int size_Mod = -1;
		public int size_Exp = -1;
		public int size_D = -1;
		public int size_P = -1;
		public int size_Q = -1;
		public int size_DP = -1;
		public int size_DQ = -1;
		public int size_InvQ = -1;
	}
}
