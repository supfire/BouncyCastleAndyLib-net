using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Signers
{
	/**
	 * EC-DSA as described in X9.62
	 */
	public class ECDsaSigner
		: IDsa
	{
		private ECKeyParameters key;
		private SecureRandom random;

		public string AlgorithmName
		{
			get { return "ECDSA"; }
		}

		public void Init(
			bool				forSigning,
			ICipherParameters	parameters)
		{
			if (forSigning)
			{
				if (parameters is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom) parameters;

					this.random = rParam.Random;
//					this.key = (ECPrivateKeyParameters) rParam.Parameters;
					parameters = rParam.Parameters;
				}
				else
				{
					this.random = new SecureRandom();
//					this.key = (ECPrivateKeyParameters) parameters;
				}

				if (!(parameters is ECPrivateKeyParameters))
					throw new InvalidKeyException("EC private key required for signing");

				this.key = (ECPrivateKeyParameters) parameters;
			}
			else
			{
				if (!(parameters is ECPublicKeyParameters))
					throw new InvalidKeyException("EC public key required for verification");

				this.key = (ECPublicKeyParameters) parameters;
			}
		}

		// 5.3 pg 28
		/**
		 * Generate a signature for the given message using the key we were
		 * initialised with. For conventional DSA the message should be a SHA-1
		 * hash of the message of interest.
		 *
		 * @param message the message that will be verified later.
		 */
		public BigInteger[] GenerateSignature(
			byte[] message)
		{
			BigInteger n = key.Parameters.N;
			BigInteger e = calculateE(n, message);

			BigInteger r = null;
			BigInteger s = null;

			// 5.3.2
			do // Generate s
			{
				BigInteger k = null;

				do // Generate r
				{
					do
					{
						k = new BigInteger(n.BitLength, random);
					}
					while (k.SignValue == 0);

					ECPoint p = key.Parameters.G.Multiply(k);

					// 5.3.3
					BigInteger x = p.X.ToBigInteger();

					r = x.Mod(n);
				}
				while (r.SignValue == 0);

				BigInteger d = ((ECPrivateKeyParameters)key).D;

				s = k.ModInverse(n).Multiply(e.Add(d.Multiply(r))).Mod(n);
			}
			while (s.SignValue == 0);

			return new BigInteger[]{ r, s };
		}

		// 5.4 pg 29
		/**
		 * return true if the value r and s represent a DSA signature for
		 * the passed in message (for standard DSA the message should be
		 * a SHA-1 hash of the real message to be verified).
		 */
		public bool VerifySignature(
			byte[]		message,
			BigInteger	r,
			BigInteger	s)
		{
			BigInteger n = key.Parameters.N;
			BigInteger e = calculateE(n, message);

			// r in the range [1,n-1]
			if (r.CompareTo(BigInteger.One) < 0 || r.CompareTo(n) >= 0)
			{
				return false;
			}

			// s in the range [1,n-1]
			if (s.CompareTo(BigInteger.One) < 0 || s.CompareTo(n) >= 0)
			{
				return false;
			}

			BigInteger c = s.ModInverse(n);

			BigInteger u1 = e.Multiply(c).Mod(n);
			BigInteger u2 = r.Multiply(c).Mod(n);

			ECPoint G = key.Parameters.G;
			ECPoint Q = ((ECPublicKeyParameters) key).Q;

			ECPoint point = G.Multiply(u1).Add(Q.Multiply(u2));

			BigInteger v = point.X.ToBigInteger().Mod(n);

			return v.Equals(r);
		}

		private BigInteger calculateE(
			BigInteger	n,
			byte[]		message)
		{
			if (n.BitLength > message.Length * 8)
			{
				return new BigInteger(1, message);
			}

			byte[] trunc = new byte[n.BitLength / 8];

			Array.Copy(message, 0, trunc, 0, trunc.Length);

			return new BigInteger(1, trunc);
		}
	}
}
