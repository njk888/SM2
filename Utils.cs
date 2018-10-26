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
                //File file2 = null;
                //byte[] pubx = CryptoUtil.toByteArray(Config.PUB_X_KEY);
                //// 公钥2
                //byte[] puby = CryptoUtil.toByteArray(Config.PUB_Y_KEY);
                //ECPoint pubKey = SMUtil.createECPoint(pubx, puby); ;
                ////需要加密文件
                //File file = new File(sourceFile);
                ////把文件变成直接数组
                //byte[] b = CryptoUtil.readFile(file);
                ////加密 返回密文数组
                //byte[] b2 = SMUtil.encryptBySM2(pubKey, b);
                ////加密写成.enc文件
                //file2 = new File(newFile);
                //if (!file2.exists())
                //{
                //    file2.createNewFile();
                //}
                //CryptoUtil.writeFile(b2, file2);


                /////////////////////////////

                FileStream fileStream = new FileStream(sourceFile, FileMode.Open);
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


                FileStream newFileStream = new FileStream(newFile, FileMode.Create);

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
        public static string encryptString(string sourceStr)
        {

            try
            {


                byte[] sourceData = UTF8Encoding.UTF8.GetBytes(sourceStr);


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

                return UTF8Encoding.UTF8.GetString(encData);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace);
                return string.Empty;
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
                ////解密
                //File file3 = null;
                //byte[] prvKey = CryptoUtil.toByteArray(Config.PRV_KEY);
                ////加密写成.enc文件
                //File file4 = new File(sourceFile);
                ////读取需要解密文件
                //byte[] prb = CryptoUtil.readFile(file4);
                ////解密 返回明文数组
                //byte[] prb2 = SMUtil.decryptBySM2(prvKey, prb);
                //file3 = new File(newFile);
                //if (!file3.getParentFile().exists())
                //{
                //    //            	boolean mkdirs = file3.getParentFile().mkdirs();
                //    file3.getParentFile().mkdirs();
                //}
                //if (!file3.exists())
                //{
                //    //				boolean createNewFile = file3.createNewFile();
                //    file3.createNewFile();
                //}
                ////解密写成.zip文件
                //CryptoUtil.writeFile(prb2, file3);


                /////////////////////////////

                FileStream fileStream = new FileStream(sourceFile, FileMode.Open);
                //文件指针指向0位置
                fileStream.Seek(0, SeekOrigin.Begin);

                byte[] encryptedData = new byte[fileStream.Length];
                fileStream.Read(encryptedData, 0, (int)fileStream.Length);
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


                FileStream newFileStream = new FileStream(newFile, FileMode.Create);

                //将字符数组转换为正确的字节格式
                //Encoder enc = Encoding.UTF8.GetEncoder();
                //enc.GetBytes(charData, 0, charData.Length, byData, 0, true);
                newFileStream.Seek(0, SeekOrigin.Begin);
                newFileStream.Write(resultData, 0, resultData.Length);
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
        public static string deccryptString(String sourceStr)
        {

            try
            {

                byte[] encryptedData = UTF8Encoding.UTF8.GetBytes(sourceStr);

                var resultData = SM2Utils.decrypt(UTF8Encoding.UTF8.GetBytes(Config.PRV_KEY), encryptedData);


                return UTF8Encoding.UTF8.GetString(resultData);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace);
                return string.Empty;
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
