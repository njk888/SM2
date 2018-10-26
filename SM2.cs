/*
 *  ecpoint类是坐标点运算
 */
using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math.EC;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace ChinaHuJinXieHuiJob.lib
{
    public class SM2
    {
        #region 使用标准参数
        public static SM2 Instance//返回错
        {
            get
            {
                return new SM2(false);
            }

        }
        #endregion

        #region 使用测试参数
        //public static SM2 InstanceTest //返回对
        //{
        //    get
        //    {
        //        return new SM2(true);
        //    }

        //}
        #endregion
        public bool sm2Test = false;//初始定义为错

        public string[] ecc_param;// = sm2_test_param;
        public readonly BigInteger ecc_p;
        public readonly BigInteger ecc_a;
        public readonly BigInteger ecc_b;
        public readonly BigInteger ecc_n;
        public readonly BigInteger ecc_gx;
        public readonly BigInteger ecc_gy;

        public readonly ECCurve ecc_curve;//椭圆曲线的产生字段
        public readonly ECPoint ecc_point_g;//g点坐标的字段

        public readonly ECDomainParameters ecc_bc_spec;
        public readonly ECKeyPairGenerator ecc_key_pair_generator;
        public ECPoint userKey;
        public BigInteger userD;
        #region ecc生成
        private SM2(bool sm2Test)
        {
            this.sm2Test = sm2Test;

            //if (sm2Test)//如果为对
            //    ecc_param = sm2_test_param;//使用国际密码管理局给的测试参数
            //else
            ecc_param = sm2_param;//否则使用国密标准256位曲线参数
            ECFieldElement ecc_gx_fieldelement;
            ECFieldElement ecc_gy_fieldelement;
            ecc_p = new BigInteger(ecc_param[0], 16);
            ecc_a = new BigInteger(ecc_param[1], 16);
            ecc_b = new BigInteger(ecc_param[2], 16);
            ecc_n = new BigInteger(ecc_param[3], 16);
            ecc_gx = new BigInteger(ecc_param[4], 16);
            ecc_gy = new BigInteger(ecc_param[5], 16);
            ecc_gx_fieldelement = new FpFieldElement(ecc_p, ecc_gx);//选定椭圆曲线上基点G的x坐标
            ecc_gy_fieldelement = new FpFieldElement(ecc_p, ecc_gy); //选定椭圆曲线上基点G的坐标
            ecc_curve = new FpCurve(ecc_p, ecc_a, ecc_b);//生成椭圆曲线
            ecc_point_g = new FpPoint(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);//生成基点G
            ecc_bc_spec = new ECDomainParameters(ecc_curve, ecc_point_g, ecc_n);//椭圆曲线，g点坐标，阶n.
            ECKeyGenerationParameters ecc_ecgenparam;
            ecc_ecgenparam = new ECKeyGenerationParameters(ecc_bc_spec, new SecureRandom());
            ecc_key_pair_generator = new ECKeyPairGenerator();
            ecc_key_pair_generator.Init(ecc_ecgenparam);
        }
        #endregion

        #region 计算Z值的方法
        /*M2签名同样也是需要先摘要原文数据，即先使用SM3密码杂凑算法计算出32byte摘要。SM3需要摘要签名方ID（默认1234567812345678）、
         * 曲线参数a,b,Gx,Gy、共钥坐标(x,y)计算出Z值，然后再杂凑原文得出摘要数据。这个地方要注意曲线参数和坐标点都是32byte，
         * 在转换为BigInteger大数计算转成字节流时要去掉空补位，否则可能会出现摘要计算不正确的问题：*/
        /// <summary>
        /// 计算Z值
        /// </summary>
        /// <param name="userId">签名方ID</param>
        /// <param name="userKey">曲线的各个参数</param>
        /// <returns></returns>
        public virtual byte[] Sm2GetZ(byte[] userId, ECPoint userKey)
        {
            SM3Digest sm3 = new SM3Digest();
            byte[] p;
            // userId length
            int len = userId.Length * 8;//求userId的长度
            sm3.Update((byte)(len >> 8 & 0x00ff));
            sm3.Update((byte)(len & 0x00ff));

            // userId
            sm3.BlockUpdate(userId, 0, userId.Length);

            // a,b
            p = ecc_a.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = ecc_b.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            // gx,gy
            p = ecc_gx.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = ecc_gy.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // x,y
            //p = userKey.X.ToBigInteger().ToByteArray();
            p = userKey.XCoord.ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            //p = userKey.Y.ToBigInteger().ToByteArray();
            p = userKey.YCoord.ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // Z
            byte[] md = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(md, 0);

            return md;
        }
        #endregion

        #region 数字签名，生成s,r;
        /*
         * SM2算法是基于ECC算法的，签名同样返回2个大数，共64byte。由于原来RSA算法已很普遍支持，
         * 要实现RSA的签名验签都有标准库的实现，而SM2是国密算法在国际上还没有标准通用，算法Oid标识在X509标准中是没定义的。
         * 在.Net或Java中可以基于使用BouncyCastle加密库实现，开源的也比较好学习扩展。SM2算法验签可以使用软验签，
         * 即可以不需要使用硬件设备，同样使用原始数据、签名、证书(公钥)来实现对签名方验证，保证数据完整性未被篡改。
         * 验证过程同样需先摘要原文数据，公钥在证书中是以一个66byte的BitString，去掉前面标记位即64byte为共钥坐标(x,y)，
         * 中间分割截取再以Hex方式转成BigInteger大数计算，验签代码如下：
         */
        /// <summary>
        /// 
        /// </summary>
        /// <param name="md">消息</param>
        /// <param name="userD">秘钥</param>
        /// <param name="userKey">公钥</param>
        /// <param name="sm2Ret">sm2Ret集合</param>
        public virtual void Sm2Sign(byte[] md, BigInteger userD, ECPoint userKey, SM2Result sm2Ret)
        {
            // e
            BigInteger e = new BigInteger(1, md);//字节转化大整数
            // k
            BigInteger k = null;//初始定义大数k为空
            ECPoint kp = null;//定义kp点为空
            BigInteger r = null;//定义大数r为空，保存求得的r值
            BigInteger s = null;//定义大数r为空，保存求得的s值

            do
            {
                do
                {
                    if (!sm2Test)//产生随机数k
                    {
                        AsymmetricCipherKeyPair keypair = ecc_key_pair_generator.GenerateKeyPair();
                        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)keypair.Private;//产生私钥
                        ECPublicKeyParameters ecpub = (ECPublicKeyParameters)keypair.Public;//产生公钥
                        k = ecpriv.D;//产生真正的k
                        kp = ecpub.Q;//kp=生成元
                    }
                    else//如果产生不了则手动添加
                    {
                        string kS = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F6CB28D99385C175C94F94E9348176240B";
                        k = new BigInteger(kS, 16);
                        kp = ecc_point_g.Multiply(k);
                    }

                    // r
                    //r = e.Add(kp.X.ToBigInteger());//r=e+kp坐标点的X
                    r = e.Add(kp.XCoord.ToBigInteger());//r=e+kp坐标点的X
                    r = r.Mod(ecc_n);//对r进行模n运算，防止越界
                }
                while (r.Equals(BigInteger.Zero) || r.Add(k).Equals(ecc_n));//r==或者0当r==n时跳出循环

                // (1 + dA)~-1
                BigInteger da_1 = userD.Add(BigInteger.One);//da_1=秘钥+1;
                da_1 = da_1.ModInverse(ecc_n);//对da_1求逆运算
                // s
                s = r.Multiply(userD);//s=r*秘钥
                s = k.Subtract(s).Mod(ecc_n);//s=((k-s)%n);
                s = da_1.Multiply(s).Mod(ecc_n);//s=((da_1*s)%n)
            }
            while (s.Equals(BigInteger.Zero));//s==0的时候跳出循环

            sm2Ret.r = r;
            sm2Ret.s = s;
        }
        #endregion

        #region 验证
        /// <summary>
        /// 
        /// </summary>
        /// <param name="md">消息</param>
        /// <param name="userKey">公钥</param>
        /// <param name="r">由数字签名得到的大数r</param>
        /// <param name="s">由数字签名得到的大数s</param>
        /// <param name="sm2Ret"></param>
        public virtual void Sm2Verify(byte[] md, ECPoint userKey, BigInteger r, BigInteger s, SM2Result sm2Ret)//客户端验证
        {
            sm2Ret.R = null;

            // e_
            BigInteger e = new BigInteger(1, md);//字节转化大整数e
            // t
            BigInteger t = r.Add(s).Mod(ecc_n);//大数t=(r+s)%n;

            if (t.Equals(BigInteger.Zero))//如果t==0，返回上一层
                return;

            // x1y1
            ECPoint x1y1 = ecc_point_g.Multiply(sm2Ret.s);//x1y1=g*s
            x1y1 = x1y1.Add(userKey.Multiply(t));//x1y1=x1y1+公钥*(t),其中t=(r+s)%n

            // R
            //sm2Ret.R = e.Add(x1y1.X.ToBigInteger()).Mod(ecc_n);//r=(x1y1点的X的大数形式+e)%n
            sm2Ret.R = e.Add(x1y1.XCoord.ToBigInteger()).Mod(ecc_n);//r=(x1y1点的X的大数形式+e)%n
        }
        #endregion

        public class SM2Result
        {
            public SM2Result()
            {
            }
            // 签名、验签
            public BigInteger r;
            public BigInteger s;
            public BigInteger R;
        }
        #region 国际密码管理局给的测试参数
        //public static readonly string[] sm2_test_param = {
        //    "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",// p,0
        //    "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",// a,1
        //    "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",// b,2
        //    "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",// n,3
        //    "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",// gx,4
        //    "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2" // gy,5
        //};
        #endregion

        #region 国密标准256位曲线参数
        public static readonly string[] sm2_param = {
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p,0
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a,1
			"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b,2
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n,3
			"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// gx,4
			"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" // gy,5
	    };
        #endregion

        #region 加密算法类
        public class Cipher
        {
            private int ct = 1;

            private ECPoint p2;
            private SM3Digest sm3keybase;
            private SM3Digest sm3c3;

            private byte[] key = new byte[32];
            private byte keyOff = 0;

            public Cipher()
            {
            }

            private void Reset()
            {
                sm3keybase = new SM3Digest();//实例化一个SM3Digest的对象sm3keybase
                sm3c3 = new SM3Digest();//实例化一个SM3Digest的对象sm3c3

                byte[] p;

                //p = p2.X.ToBigInteger().ToByteArray();//数据类型转化为比特串。
                p = p2.XCoord.ToBigInteger().ToByteArray();//数据类型转化为比特串。
                sm3keybase.BlockUpdate(p, 0, p.Length);//调用密码杂凑BlockUpdate方法
                sm3c3.BlockUpdate(p, 0, p.Length);//调用密码杂凑BlockUpdate方法

                //p = p2.Y.ToBigInteger().ToByteArray();//数据类型转化为比特串
                p = p2.YCoord.ToBigInteger().ToByteArray();//数据类型转化为比特串
                sm3keybase.BlockUpdate(p, 0, p.Length);//调用密码杂凑BlockUpdate方法

                ct = 1;
                NextKey();//调用NextKey方法
            }

            private void NextKey()
            {
                SM3Digest sm3keycur = new SM3Digest(sm3keybase);
                sm3keycur.Update((byte)(ct >> 24 & 0x00ff));//调用密码杂凑Update方法
                sm3keycur.Update((byte)(ct >> 16 & 0x00ff));//调用密码杂凑Update方法
                sm3keycur.Update((byte)(ct >> 8 & 0x00ff));//调用密码杂凑Update方法
                sm3keycur.Update((byte)(ct & 0x00ff));
                sm3keycur.DoFinal(key, 0);//调用密码杂凑DoFinal方法
                keyOff = 0;
                ct++;
            }

            public virtual ECPoint Init_enc(SM2 sm2, ECPoint userKey)
            {
                BigInteger k = null;
                ECPoint c1 = null;
                if (!sm2.sm2Test)//判断使用哪种方法
                {
                    AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
                    ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;//生成私钥
                    ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;//生成公钥
                    k = ecpriv.D;//k
                    c1 = ecpub.Q;//计算椭圆点c1
                }
                else//使用测试参数
                {
                    k = new BigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16);//指定k
                    c1 = sm2.ecc_point_g.Multiply(k);//获取公钥
                }

                p2 = userKey.Multiply(k);
                Reset();//调用密码杂凑Reset方法

                return c1;//把公钥返回给调用他得式子.
            }

            public virtual void Encrypt(byte[] data)
            {
                sm3c3.BlockUpdate(data, 0, data.Length);
                for (int i = 0; i < data.Length; i++)
                {
                    if (keyOff == key.Length)
                        NextKey();

                    data[i] ^= key[keyOff++];
                }
            }

            public virtual void Init_dec(BigInteger userD, ECPoint c1)
            {
                p2 = c1.Multiply(userD);
                Reset();//调用Reset方法
            }

            public virtual void Decrypt(byte[] data)
            {
                for (int i = 0; i < data.Length; i++)
                {
                    if (keyOff == key.Length)
                        NextKey();

                    data[i] ^= key[keyOff++];
                }
                sm3c3.BlockUpdate(data, 0, data.Length);
            }

            public virtual void Dofinal(byte[] c3)//密码杂凑中的方法
            {
                //byte[] p = p2.Y.ToBigInteger().ToByteArray();
                byte[] p = p2.YCoord.ToBigInteger().ToByteArray();
                sm3c3.BlockUpdate(p, 0, p.Length);
                sm3c3.DoFinal(c3, 0);
                Reset();
            }
        }
        #endregion

    }



    public class SM2Utils
    {
        //生成随机秘钥对  
        public static void generateKeyPair()
        {
            SM2 sm2 = SM2.Instance;
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            ECPoint publicKey = ecpub.Q;

            //System.out.println("公钥: " + Util.byteToHex(publicKey.getEncoded()));  
            //System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));  
        }

        //数据加密  
        public static String encrypt(byte[] publicKey, byte[] data)
        {
            if (publicKey == null || publicKey.Length == 0)
            {
                return null;
            }

            if (data == null || data.Length == 0)
            {
                return null;
            }

            byte[] source = new byte[data.Length];
            System.Array.Copy(data, 0, source, 0, data.Length);

            ChinaHuJinXieHuiJob.lib.SM2.Cipher cipher = new SM2.Cipher();
            SM2 sm2 = SM2.Instance;
            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);
            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);

            //      System.out.println("C1 " + Util.byteToHex(c1.getEncoded()));  
            //      System.out.println("C2 " + Util.byteToHex(source));  
            //      System.out.println("C3 " + Util.byteToHex(c3));  
            //C1 C2 C3拼装成加密字串  
            //return Util.byteToHex(c1.GetEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);
            return Utils.BytesTohexString(c1.GetEncoded()) + Utils.BytesTohexString(source) + Utils.BytesTohexString(c3);

        }

        //数据解密  
        public static byte[] decrypt(byte[] privateKey, byte[] encryptedData)
        {
            if (privateKey == null || privateKey.Length == 0)
            {
                return null;
            }

            if (encryptedData == null || encryptedData.Length == 0)
            {
                return null;
            }
            //加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2  
            //string data = Util.byteToHex(encryptedData);
            string data = Utils.BytesTohexString(encryptedData);

            /***分解加密字串 
             * （C1 = C1标志位2位 + C1实体部分128位 = 130） 
             * （C3 = C3实体部分64位  = 64） 
             * （C2 = encryptedData.length * 2 - C1长度  - C2长度） 
             */
            //byte[] c1Bytes = Util.hexToByte(data.Substring(0, 130));
            byte[] c1Bytes = Utils.HexStringToBytes(data.Substring(0, 130));
            int c2Len = encryptedData.Length - 97;
            //byte[] c2 = Util.hexToByte(data.Substring(130, 130 + 2 * c2Len));
            //byte[] c3 = Util.hexToByte(data.Substring(130 + 2 * c2Len, 194 + 2 * c2Len));
            byte[] c2 = Utils.HexStringToBytes(data.Substring(130, 130 + 2 * c2Len));
            byte[] c3 = Utils.HexStringToBytes(data.Substring(130 + 2 * c2Len, 194 + 2 * c2Len));

            SM2 sm2 = SM2.Instance;
            BigInteger userD = new BigInteger(1, privateKey);

            //通过C1实体字节来生成ECPoint  
            ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            ChinaHuJinXieHuiJob.lib.SM2.Cipher cipher = new SM2.Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            //返回解密结果  
            return c2;
        }

        //public static void main(String[] args) 
        //{  
        //    //生成密钥对  
        //    generateKeyPair();  

        //    String plainText = "ererfeiisgod";  
        //    byte[] sourceData = plainText.getBytes();  

        //    //下面的秘钥可以使用generateKeyPair()生成的秘钥内容  
        //    // 国密规范正式私钥  
        //    String prik = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";  
        //    // 国密规范正式公钥  
        //    String pubk = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";  

        //    System.out.println("加密: ");  
        //    String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);  
        //    System.out.println(cipherText);  
        //    System.out.println("解密: ");  
        //    plainText = new String(SM2Utils.decrypt(Util.hexToByte(prik), Util.hexToByte(cipherText)));  
        //    System.out.println(plainText);  

        //}  
    }

}



namespace ChinaHuJinXieHuiJob.lib
{
    public abstract class GeneralDigest : IDigest
    {
        private const int BYTE_LENGTH = 64;

        private byte[] xBuf;
        private int xBufOff;

        private long byteCount;

        internal GeneralDigest()
        {
            xBuf = new byte[4];
        }

        internal GeneralDigest(GeneralDigest t)
        {
            xBuf = new byte[t.xBuf.Length];
            Array.Copy(t.xBuf, 0, xBuf, 0, t.xBuf.Length);

            xBufOff = t.xBufOff;
            byteCount = t.byteCount;
        }

        public void Update(byte input)
        {
            xBuf[xBufOff++] = input;

            if (xBufOff == xBuf.Length)
            {
                ProcessWord(xBuf, 0);
                xBufOff = 0;
            }

            byteCount++;
        }

        public void BlockUpdate(byte[] input,int inOff,int length)
        {
            //
            // fill the current word
            //
            while ((xBufOff != 0) && (length > 0))
            {
                Update(input[inOff]);
                inOff++;
                length--;
            }

            //
            // process whole words.
            //
            while (length > xBuf.Length)
            {
                ProcessWord(input, inOff);

                inOff += xBuf.Length;
                length -= xBuf.Length;
                byteCount += xBuf.Length;
            }

            //
            // load in the remainder.
            //
            while (length > 0)
            {
                Update(input[inOff]);

                inOff++;
                length--;
            }
        }

        public void Finish()
        {
            long bitLength = (byteCount << 3);

            //
            // add the pad bytes.
            //
            Update(unchecked((byte)128));

            while (xBufOff != 0) Update(unchecked((byte)0));
            ProcessLength(bitLength);
            ProcessBlock();
        }

        public virtual void Reset()
        {
            byteCount = 0;
            xBufOff = 0;
            Array.Clear(xBuf, 0, xBuf.Length);
        }

        public int GetByteLength()
        {
            return BYTE_LENGTH;
        }

        internal abstract void ProcessWord(byte[] input, int inOff);
        internal abstract void ProcessLength(long bitLength);
        internal abstract void ProcessBlock();
        public abstract string AlgorithmName { get; }
        public abstract int GetDigestSize();
        public abstract int DoFinal(byte[] output, int outOff);
    }

    public class SupportClass
    {
        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        /// <param name="number">Number to operate on</param>
        /// <param name="bits">Ammount of bits to shift</param>
        /// <returns>The resulting number from the shift operation</returns>
        public static int URShift(int number, int bits)
        {
            if (number >= 0)
                return number >> bits;
            else
                return (number >> bits) + (2 << ~bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        /// <param name="number">Number to operate on</param>
        /// <param name="bits">Ammount of bits to shift</param>
        /// <returns>The resulting number from the shift operation</returns>
        public static int URShift(int number, long bits)
        {
            return URShift(number, (int)bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        /// <param name="number">Number to operate on</param>
        /// <param name="bits">Ammount of bits to shift</param>
        /// <returns>The resulting number from the shift operation</returns>
        public static long URShift(long number, int bits)
        {
            if (number >= 0)
                return number >> bits;
            else
                return (number >> bits) + (2L << ~bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        /// <param name="number">Number to operate on</param>
        /// <param name="bits">Ammount of bits to shift</param>
        /// <returns>The resulting number from the shift operation</returns>
        public static long URShift(long number, long bits)
        {
            return URShift(number, (int)bits);
        }


    }

    public class SM3Digest : GeneralDigest
    {
        public override string AlgorithmName
        {
            get
            {
                return "SM3";
            }

        }
        public override int GetDigestSize()
        {
            return DIGEST_LENGTH;
        }

        private const int DIGEST_LENGTH = 32;

        private static readonly int[] v0 = new int[] { 0x7380166f, 0x4914b2b9, 0x172442d7, unchecked((int)0xda8a0600), unchecked((int)0xa96f30bc), 0x163138aa, unchecked((int)0xe38dee4d), unchecked((int)0xb0fb0e4e) };

        private int[] v = new int[8];
        private int[] v_ = new int[8];

        private static readonly int[] X0 = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        private int[] X = new int[68];
        private int xOff;

        private int T_00_15 = 0x79cc4519;
        private int T_16_63 = 0x7a879d8a;

        public SM3Digest()
        {
            Reset();
        }

        public SM3Digest(SM3Digest t)
            : base(t)
        {

            Array.Copy(t.X, 0, X, 0, t.X.Length);
            xOff = t.xOff;

            Array.Copy(t.v, 0, v, 0, t.v.Length);
        }

        public override void Reset()
        {
            base.Reset();

            Array.Copy(v0, 0, v, 0, v0.Length);

            xOff = 0;
            Array.Copy(X0, 0, X, 0, X0.Length);
        }

        internal override void ProcessBlock()
        {
            int i;

            int[] ww = X;
            int[] ww_ = new int[64];

            for (i = 16; i < 68; i++)
            {
                ww[i] = P1(ww[i - 16] ^ ww[i - 9] ^ (ROTATE(ww[i - 3], 15))) ^ (ROTATE(ww[i - 13], 7)) ^ ww[i - 6];
            }

            for (i = 0; i < 64; i++)
            {
                ww_[i] = ww[i] ^ ww[i + 4];
            }

            int[] vv = v;
            int[] vv_ = v_;

            Array.Copy(vv, 0, vv_, 0, v0.Length);

            int SS1, SS2, TT1, TT2, aaa;
            for (i = 0; i < 16; i++)
            {
                aaa = ROTATE(vv_[0], 12);
                SS1 = aaa + vv_[4] + ROTATE(T_00_15, i);
                SS1 = ROTATE(SS1, 7);
                SS2 = SS1 ^ aaa;

                TT1 = FF_00_15(vv_[0], vv_[1], vv_[2]) + vv_[3] + SS2 + ww_[i];
                TT2 = GG_00_15(vv_[4], vv_[5], vv_[6]) + vv_[7] + SS1 + ww[i];
                vv_[3] = vv_[2];
                vv_[2] = ROTATE(vv_[1], 9);
                vv_[1] = vv_[0];
                vv_[0] = TT1;
                vv_[7] = vv_[6];
                vv_[6] = ROTATE(vv_[5], 19);
                vv_[5] = vv_[4];
                vv_[4] = P0(TT2);
            }
            for (i = 16; i < 64; i++)
            {
                aaa = ROTATE(vv_[0], 12);
                SS1 = aaa + vv_[4] + ROTATE(T_16_63, i);
                SS1 = ROTATE(SS1, 7);
                SS2 = SS1 ^ aaa;

                TT1 = FF_16_63(vv_[0], vv_[1], vv_[2]) + vv_[3] + SS2 + ww_[i];
                TT2 = GG_16_63(vv_[4], vv_[5], vv_[6]) + vv_[7] + SS1 + ww[i];
                vv_[3] = vv_[2];
                vv_[2] = ROTATE(vv_[1], 9);
                vv_[1] = vv_[0];
                vv_[0] = TT1;
                vv_[7] = vv_[6];
                vv_[6] = ROTATE(vv_[5], 19);
                vv_[5] = vv_[4];
                vv_[4] = P0(TT2);
            }
            for (i = 0; i < 8; i++)
            {
                vv[i] ^= vv_[i];
            }

            // Reset
            xOff = 0;
            Array.Copy(X0, 0, X, 0, X0.Length);
        }

        internal override void ProcessWord(byte[] in_Renamed, int inOff)
        {
            int n = in_Renamed[inOff] << 24;
            n |= (in_Renamed[++inOff] & 0xff) << 16;
            n |= (in_Renamed[++inOff] & 0xff) << 8;
            n |= (in_Renamed[++inOff] & 0xff);
            X[xOff] = n;

            if (++xOff == 16)
            {
                ProcessBlock();
            }
        }

        internal override void ProcessLength(long bitLength)
        {
            if (xOff > 14)
            {
                ProcessBlock();
            }

            X[14] = (int)(SupportClass.URShift(bitLength, 32));
            X[15] = (int)(bitLength & unchecked((int)0xffffffff));
        }

        public static void IntToBigEndian(int n, byte[] bs, int off)
        {
            bs[off] = (byte)(SupportClass.URShift(n, 24));
            bs[++off] = (byte)(SupportClass.URShift(n, 16));
            bs[++off] = (byte)(SupportClass.URShift(n, 8));
            bs[++off] = (byte)(n);
        }

        public override int DoFinal(byte[] out_Renamed, int outOff)
        {
            Finish();

            for (int i = 0; i < 8; i++)
            {
                IntToBigEndian(v[i], out_Renamed, outOff + i * 4);
            }

            Reset();

            return DIGEST_LENGTH;
        }

        private int ROTATE(int x, int n)
        {
            return (x << n) | (SupportClass.URShift(x, (32 - n)));
        }

        private int P0(int X)
        {
            return ((X) ^ ROTATE((X), 9) ^ ROTATE((X), 17));
        }

        private int P1(int X)
        {
            return ((X) ^ ROTATE((X), 15) ^ ROTATE((X), 23));
        }

        private int FF_00_15(int X, int Y, int Z)
        {
            return (X ^ Y ^ Z);
        }

        private int FF_16_63(int X, int Y, int Z)
        {
            return ((X & Y) | (X & Z) | (Y & Z));
        }

        private int GG_00_15(int X, int Y, int Z)
        {
            return (X ^ Y ^ Z);
        }

        private int GG_16_63(int X, int Y, int Z)
        {
            return ((X & Y) | (~X & Z));
        }

        //[STAThread]
        #region 测试并打印各个参数
        //public static void Main()
        //{
        //    byte[] msg1 = Encoding.Default.GetBytes("abc");
        //    byte[] msg2 = Encoding.Default.GetBytes("abcd");
        //    byte[] md = new byte[32];

        //    SM3Digest sm3 = new SM3Digest();

        //    // abcBlockUpdate
        //    sm3.BlockUpdate(msg1, 0, msg1.Length);
        //    sm3.DoFinal(md, 0);
        //    System.String s = new UTF8Encoding().GetString(Hex.Encode(md));
        //    System.Console.Out.WriteLine(s);

        //    // abc*16
        //    for (int i = 0; i < 16; i++)
        //        sm3.BlockUpdate(msg2, 0, msg2.Length);
        //    sm3.DoFinal(md, 0);
        //    System.String s1 = new UTF8Encoding().GetString(Hex.Encode(md));
        //    System.Console.Out.WriteLine(s1);

        //    // abc + abc*15
        //    SM3Digest sm3_ = new SM3Digest();
        //    sm3_.BlockUpdate(msg2, 0, msg2.Length);
        //    sm3 = new SM3Digest(sm3_);
        //    for (int i = 1; i < 16; i++)
        //        sm3.BlockUpdate(msg2, 0, msg2.Length);
        //    sm3.DoFinal(md, 0);
        //    System.String s2 = new UTF8Encoding().GetString(Hex.Encode(md));
        //    System.Console.Out.WriteLine(s2);
        //    Console.ReadLine();
        //    /*
        //    66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
        //    debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
        //    debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
        //    */
        //}
        #endregion
    }
}