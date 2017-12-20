using System;
using System.Collections;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>Generator for encrypted objects.</remarks>
    public class PgpEncryptedDataGenerator
		: IStreamGenerator
    {
        private BcpgOutputStream	pOut;
        private CipherStream		cOut;
        private IBufferedCipher		c;
        private bool				withIntegrityPacket;
        private bool				oldFormat;
        private DigestStream		digestOut;

		private abstract class EncMethod
            : ContainedPacket
        {
            protected byte[]                    sessionInfo;
            protected SymmetricKeyAlgorithmTag  encAlgorithm;
            protected KeyParameter              key;

			public abstract void AddSessionInfo(byte[] sessionInfo);
        }

        private class PbeMethod
            : EncMethod
        {
            private PgpEncryptedDataGenerator outer;
            private S2k s2k;

            internal PbeMethod(
                PgpEncryptedDataGenerator outer,
                SymmetricKeyAlgorithmTag  encAlgorithm,
                S2k                       s2k,
                KeyParameter              key)
            {
                this.outer = outer;
                this.encAlgorithm = encAlgorithm;
                this.s2k = s2k;
                this.key = key;
            }

            public KeyParameter GetKey()
            {
                return key;
            }

			public override void AddSessionInfo(
                byte[] sessionInfo)
            {
                string cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                IBufferedCipher c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");

                c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, new byte[c.GetBlockSize()]), outer.rand));

				this.sessionInfo = c.DoFinal(sessionInfo, 0, sessionInfo.Length - 2);
			}

			public override void Encode(BcpgOutputStream pOut)
            {
                SymmetricKeyEncSessionPacket pk = new SymmetricKeyEncSessionPacket(
                    encAlgorithm, s2k, sessionInfo);

				pOut.WritePacket(pk);
            }
        }

		private class PubMethod
            : EncMethod
        {
			internal PgpPublicKey pubKey;
            internal BigInteger[] data;

			internal PubMethod(
                PgpPublicKey pubKey)
            {
                this.pubKey = pubKey;
            }

			public override void AddSessionInfo(
                byte[] sessionInfo)
            {
                IBufferedCipher c;

				switch (pubKey.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        c = CipherUtilities.GetCipher("RSA//PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        c = CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.Dsa:
                        throw new PgpException("Can't use DSA for encryption.");
                    case PublicKeyAlgorithmTag.ECDsa:
                        throw new PgpException("Can't use ECDSA for encryption.");
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + pubKey.Algorithm);
                }

				AsymmetricKeyParameter key = pubKey.GetKey();

				c.Init(true, key);

				byte[] encKey = c.DoFinal(sessionInfo);

				switch (pubKey.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
						data = new BigInteger[]{ new BigInteger(1, encKey) };
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        byte[] b1 = new byte[encKey.Length / 2];
                        byte[] b2 = new byte[encKey.Length / 2];

						Array.Copy(encKey, 0, b1, 0, b1.Length);
                        Array.Copy(encKey, b1.Length, b2, 0, b2.Length);

						data = new BigInteger[]
						{
							new BigInteger(1, b1),
							new BigInteger(1, b2)
						};
                        break;
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + encAlgorithm);
                }
            }

			public override void Encode(BcpgOutputStream pOut)
            {
                PublicKeyEncSessionPacket pk = new PublicKeyEncSessionPacket(
                    pubKey.KeyId, pubKey.Algorithm, data);

				pOut.WritePacket(pk);
            }
        }

		private readonly ArrayList methods = new ArrayList();
        private readonly SymmetricKeyAlgorithmTag defAlgorithm;
        private readonly SecureRandom rand;

		public PgpEncryptedDataGenerator(
			SymmetricKeyAlgorithmTag encAlgorithm)
		{
			this.defAlgorithm = encAlgorithm;
			this.rand = new SecureRandom();
		}

		public PgpEncryptedDataGenerator(
			SymmetricKeyAlgorithmTag	encAlgorithm,
			bool						withIntegrityPacket)
		{
			this.defAlgorithm = encAlgorithm;
			this.withIntegrityPacket = withIntegrityPacket;
			this.rand = new SecureRandom();
		}

		/// <summary>Existing SecureRandom constructor.</summary>
		/// <param name="encAlgorithm">The symmetric algorithm to use.</param>
		/// <param name="rand">Source of randomness.</param>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag	encAlgorithm,
            SecureRandom				rand)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = rand;
        }

		/// <summary>Creates a cipher stream which will have an integrity packet associated with it.</summary>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag	encAlgorithm,
            bool						withIntegrityPacket,
            SecureRandom				rand)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = rand;
            this.withIntegrityPacket = withIntegrityPacket;
        }

		/// <summary>Base constructor.</summary>
		/// <param name="encAlgorithm">The symmetric algorithm to use.</param>
		/// <param name="rand">Source of randomness.</param>
		/// <param name="oldFormat">PGP 2.6.x compatibility required.</param>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag	encAlgorithm,
            SecureRandom				rand,
            bool						oldFormat)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = rand;
            this.oldFormat = oldFormat;
        }

		/// <summary>Add a PBE encryption method to the encrypted object.</summary>
        public void AddMethod(
            char[] passPhrase)
        {
            byte[] iv = new byte[8];
			rand.NextBytes(iv);

			S2k s2k = new S2k(HashAlgorithmTag.Sha1, iv, 0x60);

			methods.Add(new PbeMethod(this, defAlgorithm, s2k, PgpUtilities.MakeKeyFromPassPhrase(defAlgorithm, s2k, passPhrase)));
        }

		/// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        public void AddMethod(
            PgpPublicKey key)
        {
			if (!key.IsEncryptionKey)
            {
                throw new ArgumentException("passed in key not an encryption key!");
            }

			methods.Add(new PubMethod(key));
        }

		private void AddCheckSum(
            byte[] sessionInfo)
        {
			Debug.Assert(sessionInfo != null);
			Debug.Assert(sessionInfo.Length >= 3);

			int check = 0;

			for (int i = 1; i < sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i];
            }

			sessionInfo[sessionInfo.Length - 2] = (byte)(check >> 8);
            sessionInfo[sessionInfo.Length - 1] = (byte)(check);
        }

		private byte[] CreateSessionInfo(
			SymmetricKeyAlgorithmTag	algorithm,
			KeyParameter				key)
		{
			byte[] keyBytes = key.GetKey();
			byte[] sessionInfo = new byte[keyBytes.Length + 3];
			sessionInfo[0] = (byte) algorithm;
			keyBytes.CopyTo(sessionInfo, 1);
			AddCheckSum(sessionInfo);
			return sessionInfo;
		}

		/// <summary>
		/// If buffer is non null stream assumed to be partial, otherwise the length will be used
		/// to output a fixed length packet. The stream can be closed off by either calling Close()
		/// on the stream or Close() on the generator.
		/// </summary>
        private Stream Open(
            Stream	outStr,
            long	length,
            byte[]	buffer)
        {
			if (cOut != null)
				throw new InvalidOperationException("generator already in open state");
			if (methods.Count == 0)
				throw new InvalidOperationException("No encryption methods specified");
			if (outStr == null)
				throw new ArgumentNullException("outStr");

			pOut = new BcpgOutputStream(outStr);

			KeyParameter key = null;

			if (methods.Count == 1)
            {
                if (methods[0] is PbeMethod)
                {
                    PbeMethod m = (PbeMethod)methods[0];

					key = m.GetKey();
                }
                else
                {
                    key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);

					byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);
                    PubMethod m = (PubMethod)methods[0];

                    try
                    {
                        m.AddSessionInfo(sessionInfo);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }
                }

				pOut.WritePacket((ContainedPacket)methods[0]);
            }
            else // multiple methods
            {
                key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);
				byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

				for (int i = 0; i != methods.Count; i++)
                {
                    EncMethod m = (EncMethod)methods[i];

                    try
                    {
                        m.AddSessionInfo(sessionInfo);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }

                    pOut.WritePacket(m);
                }
            }

            string cName = PgpUtilities.GetSymmetricCipherName(defAlgorithm);
			if (cName == null)
            {
                throw new PgpException("null cipher specified");
            }

			try
            {
                if (withIntegrityPacket)
                {
                    cName += "/CFB/NoPadding";
                }
                else
                {
                    cName += "/OpenPGPCFB/NoPadding";
                }

                c = CipherUtilities.GetCipher(cName);

				// TODO Confirm the IV should be all zero bytes (not inLineIv - see below)
                c.Init(true, new ParametersWithIV(key, new byte[c.GetBlockSize()]));

                if (buffer == null)
                {
                    //
                    // we have to Add block size + 2 for the Generated IV and + 1 + 22 if integrity protected
                    //
                    if (withIntegrityPacket)
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, length + c.GetBlockSize() + 2 + 1 + 22);
                        pOut.WriteByte(1);        // version number
                    }
                    else
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, length + c.GetBlockSize() + 2, oldFormat);
                    }
                }
                else
                {
                    if (withIntegrityPacket)
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, buffer);
                        pOut.WriteByte(1);        // version number
                    }
                    else
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, buffer);
                    }
                }

				int blockSize = c.GetBlockSize();
				byte[] inLineIv = new byte[blockSize + 2];
                rand.NextBytes(inLineIv, 0, blockSize);
				Array.Copy(inLineIv, inLineIv.Length - 4, inLineIv, inLineIv.Length - 2, 2);

				Stream myOut = cOut = new CipherStream(pOut, null, c);

				if (withIntegrityPacket)
                {
					string digestName = PgpUtilities.GetDigestName(HashAlgorithmTag.Sha1);
					IDigest digest = DigestUtilities.GetDigest(digestName);
					myOut = digestOut = new DigestStream(myOut, null, digest);
                }

				myOut.Write(inLineIv, 0, inLineIv.Length);

				return new WrappedGeneratorStream(this, myOut);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

		/// <summary>
		/// Return an output stream which will encrypt the data as it is written to it.
		/// The stream can be closed off by either calling Close() on the stream or
		/// Close() on the generator.
		/// </summary>
        public Stream Open(
            Stream	outStr,
            long	length)
        {
            return this.Open(outStr, length, null);
        }

		/// <summary>
		/// Return an output stream which will encrypt the data as it is written to it.
		/// The stream will be written out in chunks according to the size of the passed in buffer.
		/// The stream can be closed off by either calling Close() on the stream or Close()
		/// on the generator.
		/// <p>
		/// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
		/// bytes worth of the buffer will be used.
		/// </p>
		/// </summary>
        public Stream Open(
            Stream	outStr,
            byte[]	buffer)
        {
            return this.Open(outStr, 0, buffer);
        }

		/// <summary>
		/// Close off the encrypted object - this is equivalent to calling Close() on the stream
		/// returned by the Open() method.
		/// </summary>
        public void Close()
        {
            if (cOut != null)
            {
				// TODO Should this all be under the try/catch block?
                if (digestOut != null)
                {
                    //
                    // hand code a mod detection packet
                    //
                    BcpgOutputStream bOut = new BcpgOutputStream(
						digestOut, PacketTag.ModificationDetectionCode, 20);

                    bOut.Flush();
                    digestOut.Flush();

					// TODO
					byte[] dig = DigestUtilities.DoFinal(digestOut.WriteDigest());
					cOut.Write(dig, 0, dig.Length);
                }

				cOut.Flush();

				try
                {
					pOut.Write(c.DoFinal());
                    pOut.Finish();
                }
                catch (Exception e)
                {
                    throw new IOException(e.Message, e);
                }

				cOut = null;
				pOut = null;
            }
		}
	}
}