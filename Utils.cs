using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ChinaHuJinXieHuiJob.lib
{
    public class Utils
    {

        /// <summary>
        /// 获取指定长度的随机数
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static String getRandomNumber(int length)
        {
            String result = "";
            Random rnd = new Random();
            for (int i = 0; i < length; i++)
            {
                result += rnd.Next(10);
            }
            return result;
        }

        public static string SHA256Encrypt(string strIN)
        {
            byte[] bytValue = System.Text.Encoding.UTF8.GetBytes(strIN);
            try
            {
                SHA256 sha256 = new SHA256CryptoServiceProvider();
                byte[] retVal = sha256.ComputeHash(bytValue);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < retVal.Length; i++)
                {
                    sb.Append(retVal[i].ToString("x2"));
                }
                return sb.ToString();
            }
            catch (Exception ex)
            {
                throw new Exception("GetSHA256HashFromString() fail,error:" + ex.Message);
            }

        }


        /// <summary>
        /// 字符串转md5
        /// </summary>
        /// <param name="inputStr"></param>
        /// <returns></returns>
        private string string2Md5(string inputStr)
        {
            MD5CryptoServiceProvider md5Hasher = new MD5CryptoServiceProvider();
            byte[] data = md5Hasher.ComputeHash(Encoding.UTF8.GetBytes(inputStr));
            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }
            return sBuilder.ToString();
        }

      
        /// <summary>
        /// 国密加密文件 zip转enc
        /// </summary>
        /// <param name="sourceFile"></param>
        /// <param name="newFile"></param>
        /// <returns></returns>
        public static bool encryptFile(string sourceFile, string newFile)
        {

            try
            {
                /////////////////////////////

                FileStream fileStream = new FileStream(sourceFile, FileMode.Open,FileAccess.Read);
                //文件指针指向0位置
                fileStream.Seek(0, SeekOrigin.Begin);

                byte[] sourceData = new byte[fileStream.Length];
                fileStream.Read(sourceData, 0, (int)fileStream.Length);
                fileStream.Close();

                //加密 返回密文数组
                //byte[] b2 = SMUtil.encryptBySM2(pubKey, b);
                SM2 sm2 = SM2.Instance;
                string strcertPKX = Config.PUB_X_KEY;
                string strcertPKY = Config.PUB_Y_KEY;
                BigInteger biX = new BigInteger(strcertPKX, 16);
                BigInteger biY = new BigInteger(strcertPKY, 16);
                ECFieldElement x = new FpFieldElement(sm2.ecc_p, biX);
                ECFieldElement y = new FpFieldElement(sm2.ecc_p, biY);
                ECPoint userKey = new FpPoint(sm2.ecc_curve, x, y);


                ChinaHuJinXieHuiJob.lib.SM2.Cipher cipher = new SM2.Cipher();
                ECPoint c1 = cipher.Init_enc(sm2, userKey);
                byte[] source = new byte[sourceData.Length];
                System.Array.Copy(sourceData, 0, source, 0, sourceData.Length);


               
                cipher.Encrypt(source);
                byte[] c3 = new byte[32];
                cipher.Dofinal(c3);


                byte[] encData = new byte[c1.GetEncoded().Length + source.Length + c3.Length];
                System.Array.Copy(c1.GetEncoded(), 0, encData, 0, c1.GetEncoded().Length);
                System.Array.Copy(source, 0, encData, c1.GetEncoded().Length, source.Length);
                System.Array.Copy(c3, 0, encData, c1.GetEncoded().Length + source.Length, c3.Length);


                FileStream newFileStream = new FileStream(newFile, FileMode.CreateNew);

                //将字符数组转换为正确的字节格式
                //Encoder enc = Encoding.UTF8.GetEncoder();
                //enc.GetBytes(charData, 0, charData.Length, byData, 0, true);
                newFileStream.Seek(0, SeekOrigin.Begin);
                newFileStream.Write(encData, 0, encData.Length);
                newFileStream.Close();

            }
            catch (Exception e)
            {
                return false;
            }
            return true;
        }

        /// <summary>
        /// 国密加密字符串 
        /// </summary>
        /// <param name="sourceFile"></param>
        /// <param name="newFile"></param>
        /// <returns></returns>
        public static byte[] encryptString(byte[] data)
        {
            try
            {
                //byte[] sourceData = UTF8Encoding.UTF8.GetBytes(sourceStr);
                byte[] source = new byte[data.Length];
                System.Array.Copy(data, 0, source, 0, data.Length);


                //加密 返回密文数组
                ChinaHuJinXieHuiJob.lib.SM2.Cipher cipher = new SM2.Cipher();

                SM2 sm2 = SM2.Instance;
                BigInteger biX = new BigInteger(Config.PUB_X_KEY, 16);
                BigInteger biY = new BigInteger(Config.PUB_Y_KEY, 16);

                ECPoint userKey = sm2.ecc_curve.CreatePoint(biX, biY);
                ECPoint c1 = cipher.Init_enc(sm2, userKey);
         
                cipher.Encrypt(source);
                byte[] c3 = new byte[32];
                cipher.Dofinal(c3);

                byte[] encData = new byte[c1.GetEncoded().Length + source.Length + c3.Length];
                System.Array.Copy(c1.GetEncoded(), 0, encData, 0, c1.GetEncoded().Length);
                System.Array.Copy(source, 0, encData, c1.GetEncoded().Length, source.Length);
                System.Array.Copy(c3, 0, encData, c1.GetEncoded().Length + source.Length, c3.Length);

                return  encData;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace);
                return null;
            }
        }


        /// <summary>
        /// 国密解密文件  
        /// </summary>
        /// <param name="sourceFile"></param>
        /// <param name="newFile"></param>
        /// <returns></returns>
        public static bool deccryptFile(String sourceFile, String newFile)
        {

            try
            {
                /////////////////////////////

                FileStream fileStream = new FileStream(sourceFile, FileMode.Open,FileAccess.Read);

                BinaryReader sr = new BinaryReader(fileStream);

                //byte[] encryptedData = Encoding.ASCII.GetBytes(sr.r));
                byte[] encryptedData= sr.ReadBytes((int)fileStream.Length);
                //文件指针指向0位置
                //fileStream.Seek(0, SeekOrigin.Begin);

                //byte[] encryptedData = new byte[fileStream.Length];
                //fileStream.Read(encryptedData, 0, (int)fileStream.Length);

                sr.Close();
                fileStream.Close();

                //加密 返回密文数组

                //byte[] encData = new byte[100];
                ////byte[] b2 = SMUtil.encryptBySM2(pubKey, b);
                //SM2 sm2 = SM2.Instance;
                //string strcertPKX = Config.PUB_X_KEY;
                //string strcertPKY = Config.PUB_Y_KEY;
                //BigInteger biX = new BigInteger(strcertPKX, 16);
                //BigInteger biY = new BigInteger(strcertPKY, 16);
                //ECFieldElement x = new FpFieldElement(sm2.ecc_p, biX);
                //ECFieldElement y = new FpFieldElement(sm2.ecc_p, biY);
                //ECPoint userKey = new FpPoint(sm2.ecc_curve, x, y);
                //SM2.SM2Result sm2Result = new SM2.SM2Result();
                //BigInteger userD = new BigInteger(Config.PRV_KEY, 16);

                //ChinaHuJinXieHuiJob.lib.SM2.Cipher cipher = new SM2.Cipher();


                ////加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2

                //string data = BitConverter.ToString(encryptedData);
                //data = BitConverter.ToString(encryptedData).Replace("-", "");
                ///***分解加密字串
                // * （C1 = C1标志位2位 + C1实体部分128位 = 130）
                // * （C3 = C3实体部分64位  = 64）
                // * （C2 = encryptedData.length * 2 - C1长度  - C2长度）
                // */
                //byte[] c1Bytes = HexStringToBytes(data.Substring(0, 130));
                //int c2Len = encryptedData.Length - 97;
                //byte[] resultData = HexStringToBytes(data.Substring(130, 130 + 2 * c2Len));
                //byte[] c3 = HexStringToBytes(data.Substring(130 + 2 * c2Len, 194 + 2 * c2Len));


                //// BigInteger userD = new BigInteger(1, privateKey);

                ////通过C1实体字节来生成ECPoint
                //ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
                //cipher.Init_dec(userD, c1);   //userKey
                //cipher.Decrypt(resultData);
                //cipher.Dofinal(c3);

                var resultData = SM2Utils.decrypt(UTF8Encoding.UTF8.GetBytes(Config.PRV_KEY) ,encryptedData);


                FileStream newFileStream = new FileStream(newFile, FileMode.CreateNew);
                BinaryWriter bw = new BinaryWriter(newFileStream);
                //将字符数组转换为正确的字节格式
                //Encoder enc = Encoding.UTF8.GetEncoder();
                //enc.GetBytes(charData, 0, charData.Length, byData, 0, true);
                bw.Seek(0, SeekOrigin.Begin);
                bw.Write(resultData, 0, resultData.Length);
                bw.Close();
                newFileStream.Close();
            }
            catch (Exception e)
            {
                return false;
            }
            return true;
        }


        /// <summary>
        /// 国密解密字符串 env转zip
        /// </summary>
        /// <param name="sourceFile"></param>
        /// <param name="newFile"></param>
        /// <returns></returns>
        public static byte[] deccryptString(byte[] sourceStr)
        {

            try
            {

               // byte[] encryptedData = Convert.FromBase64String(sourceStr);

                BigInteger bigPrivateKey = new BigInteger(Config.PRV_KEY, 16);
                var resultData = SM2Utils.decrypt(bigPrivateKey.ToByteArray(), sourceStr);


                return  resultData;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace);
                return null;
            }
            
        }

        


        /// <summary>
        /// 十六进制字符串转byte数组
        /// </summary>
        /// <param name="hexStr"></param>
        /// <returns></returns>
        public static byte[] HexStringToBytes(string hexStr)
        {
            if (string.IsNullOrEmpty(hexStr))
            {
                return new byte[0];
            }

            if (hexStr.StartsWith("0x"))
            {
                hexStr = hexStr.Remove(0, 2);
            }

            var count = hexStr.Length;

            if (count % 2 == 1)
            {
                throw new ArgumentException("Invalid length of bytes:" + count);
            }

            var byteCount = count / 2;
            var result = new byte[byteCount];
            for (int ii = 0; ii < byteCount; ++ii)
            {
                var tempBytes = Byte.Parse(hexStr.Substring(2 * ii, 2), System.Globalization.NumberStyles.HexNumber);
                result[ii] = tempBytes;
            }

            return result;
        }

        //public static byte charToByte(char c)
        //{
        //    return (byte)"0123456789ABCDEF".IndexOf(c);
        //}

        /// <summary>
        /// byte数组转十六进制字符串(没有0x）
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string BytesTohexString(byte[] bytes)
        {
            if (bytes == null || bytes.Count() < 1)
            {
                return string.Empty;
            }

            var count = bytes.Count();

            var cache = new StringBuilder();
            //cache.Append("0x");
            for (int ii = 0; ii < count; ++ii)
            {
                var tempHex = Convert.ToString(bytes[ii], 16);
                cache.Append(tempHex.Length == 1 ? "0" + tempHex : tempHex);
            }

            return cache.ToString();
        }
    }

    
}
