using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System.IO;
using System.Text;

namespace PGP
{
    public class PgpHelper
    {




        /// <summary>
        /// Encrypts the provided plaintext data using the specified PGP public key.
        /// </summary>
        /// <param name="encryptionKey">The PGP public key used for encryption.</param>
        /// <param name="plainText">The plaintext data to be encrypted.</param>
        /// <returns>The encrypted data as a byte array.</returns>
        private static byte[] EncryptDataWithPublicKey(PgpPublicKey encryptionKey, byte[] plainText)
        {
            // Create a MemoryStream to store the encrypted data.
            using (MemoryStream encryptedStream = new())
            {
                // Create a PgpLiteralDataGenerator to generate literal data packets in PGP.
                PgpLiteralDataGenerator lData = new();

                // Open a stream with the PgpLiteralDataGenerator and write the plaintext data into a literal data packet.
                using (Stream literalDataStream = lData.Open(encryptedStream,
                                                                            PgpLiteralData.Binary,
                                                                            PgpLiteralData.Console,
                                                                            plainText.Length,
                                                                            DateTime.UtcNow))
                {
                    literalDataStream.Write(plainText, 0, plainText.Length);
                }


                // Create a MemoryStream to store the final result.
                using (MemoryStream resultStream = new())
                {
                    // Create a PgpEncryptedDataGenerator with the specified symmetric key algorithm, enabling integrity protection.
                    PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(
                        SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());

                    // Add the encryption key to the generator.
                    encryptedDataGenerator.AddMethod(encryptionKey);

                    // Open a stream with the encryptedDataGenerator and write the encrypted data into the result stream.
                    using (Stream compressedOut = encryptedDataGenerator.Open(resultStream, encryptedStream.ToArray().Length))
                    {
                        compressedOut.Write(encryptedStream.ToArray(), 0, encryptedStream.ToArray().Length);
                    }

                    // Return the encrypted data as a byte array.
                    return resultStream.ToArray();
                }
            }
        }


        /// <summary>
        /// Decrypts PGP encrypted data using the provided private key and returns the decrypted bytes.
        /// </summary>
        /// <param name="privateKey">The PGP private key used for decryption.</param>
        /// <param name="encryptedB64String">The base64-encoded PGP encrypted data.</param>
        /// <returns>The decrypted data as a byte array.</returns>
        /// <exception cref="Exception">Thrown in case of decryption failure or IO exceptions.</exception>
        private static byte[] DecryptDataWithPrivateKey(PgpPrivateKey privateKey, string encryptedB64String)
        {
            try
            {
                // Convert the base64-encoded PGP encrypted data to a byte array
                byte[] pgpEncryptedData = Convert.FromBase64String(encryptedB64String);

                // Create a PgpObjectFactory for parsing the PGP encrypted data
                PgpObjectFactory pgpFact = new(pgpEncryptedData);

                // Obtain the first object, which should be a PgpEncryptedDataList
                PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpFact.NextPgpObject();

                // Find the correct PgpPublicKeyEncryptedData using the provided private key
                PgpPublicKeyEncryptedData? encData = null;
                foreach (PgpPublicKeyEncryptedData data in encList.GetEncryptedDataObjects())
                {
                    if (data.KeyId == privateKey.KeyId)
                    {
                        encData = data;
                        break;
                    }
                }

                if (encData == null)
                {
                    throw new PgpException("Provided private key not found in encrypted data.");
                }

                // Create a decrypted stream
                Stream clear = encData.GetDataStream(privateKey);

                // Create a new MemoryStream to hold the decrypted data
                using (MemoryStream decryptedStream = new MemoryStream())
                {
                    // Read the decrypted data into the MemoryStream
                    Streams.PipeAll(clear, decryptedStream);

                    // Verify the integrity of the decrypted data
                    if (encData.Verify())
                    {
                        // Create a PgpObjectFactory for parsing the decrypted literal data
                        PgpObjectFactory litFact = new PgpObjectFactory(decryptedStream.ToArray());

                        // Obtain the literal data packet
                        PgpLiteralData litData = (PgpLiteralData)litFact.NextPgpObject();

                        // Read the actual data from the literal data input stream
                        using (Stream dataStream = litData.GetInputStream())
                        {
                            byte[] data = Streams.ReadAll(dataStream);
                            return data;
                        }
                    }
                    else
                    {
                        throw new PgpException("Modification check failed.");
                    }
                }
            }
            catch (PgpException ex)
            {
                throw new Exception("Decryption failed: " + ex.Message, ex);
            }
            catch (IOException ex)
            {
                throw new Exception("IO exception during decryption: " + ex.Message, ex);
            }
        }



        /// <summary>
        /// Gets the public key from an pgp amoured file ie. asc
        /// </summary>
        /// <param name="publicKeyFilePath"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static PgpPublicKey? GetPgpPubKey(string publicKeyFilePath)
        {
            using (Stream keyFileStream = File.OpenRead(publicKeyFilePath))
            using (ArmoredInputStream armoredInputStream = new(keyFileStream))
            {
                try
                {
                    // Read the contents of the ArmoredInputStream into a byte array
                    byte[] keyData = Streams.ReadAll(armoredInputStream);

                    // Create a new stream from the byte array
                    using Stream keyDataStream = new MemoryStream(keyData);
                    PgpPublicKeyRingBundle publicKeyRingBundle = new(keyDataStream);

                    // Assuming you want the first public key in the file
                    PgpPublicKeyRing publicKeyRing = publicKeyRingBundle.GetKeyRings().OfType<PgpPublicKeyRing>().FirstOrDefault();

                    if (publicKeyRing != null)
                    {
                        return publicKeyRing.GetPublicKeys().OfType<PgpPublicKey>().FirstOrDefault();
                    }
                    else
                    {
                        throw new InvalidOperationException("No public key ring found in the specified key file.");
                    }
                }
                catch (PgpException ex)
                {
                    Console.WriteLine($"Error reading the key file: {ex.Message}");
                    return null;
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"IO error reading the key file: {ex.Message}");
                    return null;
                }
            }
        }

        /// <summary>
        /// Gets the private key from a pgp amoured file ie. asc
        /// </summary>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passphrase"></param>
        /// <returns></returns>
        private static PgpPrivateKey? GetPgpPrivateKey(string privateKeyFilePath, string passphrase)
        {
            try
            {
                PgpSecretKeyRing secretKeyRing;
                using (var keyFileStream = new FileStream(privateKeyFilePath, FileMode.Open))
                {
                    secretKeyRing = new PgpSecretKeyRing(PgpUtilities.GetDecoderStream(keyFileStream));
                }

                PgpSecretKey secretKey = secretKeyRing.GetSecretKey();
                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey($"{passphrase}".ToCharArray());

                return privateKey;
            }
            catch (Exception ex)
            {
                // Handle exceptions, log errors, or take appropriate action.
                Console.WriteLine($"Error reading PGP private key from file: {ex.Message}");
                return null;
                throw;
            }
        }


        /// <summary>
        /// Encrypt string content
        /// </summary>
        /// <param name="pathToPubKey">Path to Public key</param>
        /// <param name="ContentToEncrypt">Content as text to encrypt</param>
        /// <returns>Encrypted string</returns>
        public static string EncryptData(string ContentToEncrypt)
        {
            string pathToPubKey = string.Empty;
            var pubKey = GetPgpPubKey(pathToPubKey);

            if (pubKey == null)
            {
                return string.Empty;
            }

            var encrypted = EncryptDataWithPublicKey(pubKey, Encoding.UTF8.GetBytes(ContentToEncrypt));


            return Convert.ToBase64String(encrypted);


        }


        /// <summary>
        /// Decrypt string content
        /// </summary>
        /// <param name="pathToPrivKey">Path to Private key</param>
        /// <param name="passphrase">Key passphrase</param>
        /// <param name="ContentToDecrypt">Content as text to encrypt</param>
        /// <returns>Encrypted string</returns>
        public static string DecryptData(string pathToPrivKey, string passphrase, string ContentToDecrypt)
        {

            var privKey = GetPgpPrivateKey(pathToPrivKey, passphrase);

            if (privKey == null)
            {
                return string.Empty;
            }

            var decrypted = DecryptDataWithPrivateKey(privKey, ContentToDecrypt);

            return Encoding.UTF8.GetString(decrypted);
        }

    }

}