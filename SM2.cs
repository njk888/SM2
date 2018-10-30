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
        public byte[] Sm2GetZ(byte[] userId, ECPoint userKey)
        {
            SM3Digest sm3 = new SM3Digest();
            byte[] p;
            // userId length
            int len = userId.Length * 8;
            sm3.update((byte)(len >> 8 & 0x00ff));
            sm3.update((byte)(len & 0x00ff));

            // userId
            sm3.update(userId, 0, userId.Length);

            // a,b
            p = ecc_a.ToByteArray();
            sm3.update(p, 0, p.Length);
            p = ecc_b.ToByteArray();
            sm3.update(p, 0, p.Length);
            // gx,gy
            p = ecc_gx.ToByteArray();
            sm3.update(p, 0, p.Length);
            p = ecc_gy.ToByteArray();
            sm3.update(p, 0, p.Length);

            // x,y
            p = userKey.XCoord.GetEncoded();
            sm3.update(p, 0, p.Length);
            p = userKey.YCoord.GetEncoded();
            sm3.update(p, 0, p.Length);

            // Z
            byte[] md = new byte[sm3.getDigestSize()];
            sm3.doFinal(md, 0);

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
                this.sm3keybase = new SM3Digest();
                this.sm3c3 = new SM3Digest();

                byte[] p = Util.byteConvert32Bytes(p2.XCoord.ToBigInteger());
                this.sm3keybase.update(p, 0, p.Length);
                this.sm3c3.update(p, 0, p.Length);

                p = Util.byteConvert32Bytes(p2.YCoord.ToBigInteger());
                this.sm3keybase.update(p, 0, p.Length);
                this.ct = 1;
                NextKey();

            }

            private void NextKey()
            {
                SM3Digest sm3keycur = new SM3Digest();
                sm3keycur.update((byte)(ct >> 24 & 0x00ff));//调用密码杂凑Update方法
                sm3keycur.update((byte)(ct >> 16 & 0x00ff));//调用密码杂凑Update方法
                sm3keycur.update((byte)(ct >> 8 & 0x00ff));//调用密码杂凑Update方法
                sm3keycur.update((byte)(ct & 0x00ff));
                sm3keycur.doFinal(key, 0);//调用密码杂凑DoFinal方法
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
                sm3c3.update(data, 0, data.Length);
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
                sm3c3.update(data, 0, data.Length);
            }

            public virtual void Dofinal(byte[] c3)//密码杂凑中的方法
            {
                //byte[] p = p2.Y.ToBigInteger().ToByteArray();
                byte[] p = p2.YCoord.ToBigInteger().ToByteArray();
                sm3c3.update(p, 0, p.Length);
                sm3c3.doFinal(c3, 0);
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
        public static byte[] encrypt(byte[] publicKey, byte[] data)
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

            byte[] result = new byte[c1.GetEncoded().Length + source.Length + c3.Length];
            Array.Copy(c1.GetEncoded(), 0, result, 0, 65);
            Array.Copy(source, 0, result, 65, source.Length);
            Array.Copy(c3, 0, result, 65 + source.Length, 32);

            return result;

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
            /***分解加密字串 
             * （C1 = C1标志位2位 + C1实体部分128位 = 130） 
             * （C3 = C3实体部分64位  = 64） 
             * （C2 = encryptedData.length * 2 - C1长度  - C2长度） 
             */
            byte[] c1Bytes = new byte[65];
            Array.Copy(encryptedData, 0, c1Bytes, 0, 65);
            int c2Len = encryptedData.Length - 97;
            byte[] c2 = new byte[c2Len];
            Array.Copy(encryptedData, 65, c2, 0, c2Len);
            byte[] c3 = new byte[32];
            Array.Copy(encryptedData, c2Len + 65, c3, 0, 32);

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


    public class SM3Digest
    {


        /** SM3值的长度 */
        private static readonly int BYTE_LENGTH = 32;

        /** SM3分组长度 */
        private static readonly int BLOCK_LENGTH = 64;

        /** 缓冲区长度 */
        private static readonly int BUFFER_LENGTH = BLOCK_LENGTH * 1;

        /** 缓冲区 */
        private byte[] xBuf = new byte[BUFFER_LENGTH];

        /** 缓冲区偏移量 */
        private int xBufOff;

        /** 初始向量 */
        private byte[] V = (byte[])SM3.iv.Clone();

        private int cntBlock = 0;

        public SM3Digest()
        {
        }

        public SM3Digest(SM3Digest t)
        {
            System.Array.Copy(t.xBuf, 0, this.xBuf, 0, t.xBuf.Length);
            this.xBufOff = t.xBufOff;
            System.Array.Copy(t.V, 0, this.V, 0, t.V.Length);
        }

        /**
         * SM3结果输出
         * 
         * @param out 保存SM3结构的缓冲区
         * @param outOff 缓冲区偏移量
         * @return
         */
        public int doFinal(byte[] outData, int outOff)
        {
            byte[] tmp = doFinal();
            System.Array.Copy(tmp, 0, outData, 0, tmp.Length);
            return BYTE_LENGTH;
        }

        public void reset()
        {
            xBufOff = 0;
            cntBlock = 0;
            V = (byte[])SM3.iv.Clone();
        }

        /**
         * 明文输入
         * 
         * @param in
         *            明文输入缓冲区
         * @param inOff
         *            缓冲区偏移量
         * @param len
         *            明文长度
         */
        public void update(byte[] inData, int inOff, int len)
        {
            int partLen = BUFFER_LENGTH - xBufOff;
            int inputLen = len;
            int dPos = inOff;
            if (partLen < inputLen)
            {
                System.Array.Copy(inData, dPos, xBuf, xBufOff, partLen);
                inputLen -= partLen;
                dPos += partLen;
                doUpdate();
                while (inputLen > BUFFER_LENGTH)
                {
                    System.Array.Copy(inData, dPos, xBuf, 0, BUFFER_LENGTH);
                    inputLen -= BUFFER_LENGTH;
                    dPos += BUFFER_LENGTH;
                    doUpdate();
                }
            }

            System.Array.Copy(inData, dPos, xBuf, xBufOff, inputLen);
            xBufOff += inputLen;
        }

        private void doUpdate()
        {
            byte[] B = new byte[BLOCK_LENGTH];
            for (int i = 0; i < BUFFER_LENGTH; i += BLOCK_LENGTH)
            {
                System.Array.Copy(xBuf, i, B, 0, B.Length);
                doHash(B);
            }
            xBufOff = 0;
        }

        private void doHash(byte[] B)
        {
            byte[] tmp = SM3.CF(V, B);
            System.Array.Copy(tmp, 0, V, 0, V.Length);
            cntBlock++;
        }

        private byte[] doFinal()
        {
            byte[] B = new byte[BLOCK_LENGTH];
            byte[] buffer = new byte[xBufOff];
            System.Array.Copy(xBuf, 0, buffer, 0, buffer.Length);
            byte[] tmp = SM3.padding(buffer, cntBlock);
            for (int i = 0; i < tmp.Length; i += BLOCK_LENGTH)
            {
                System.Array.Copy(tmp, i, B, 0, B.Length);
                doHash(B);
            }
            return V;
        }

        public void update(byte inData)
        {
            byte[] buffer = new byte[] { inData };
            update(buffer, 0, 1);
        }

        public int getDigestSize()
        {
            return BYTE_LENGTH;
        }

        //public static void main(String[] args) 
        //{
        //    byte[] md = new byte[32];
        //    byte[] msg1 = "ererfeiisgod".getBytes();
        //    SM3Digest sm3 = new SM3Digest();
        //    sm3.update(msg1, 0, msg1.length);
        //    sm3.doFinal(md, 0);
        //    String s = new String(Hex.encode(md));
        //    System.out.println(s.toUpperCase());
        //}
    }

    public class SM3
    {
        public static readonly byte[] iv = new BigInteger("7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e", 16).ToByteArray();

        public static int[] Tj = {
                                 0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519
                                 ,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
                                 ,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
                                 ,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
                                 ,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
                             };

        public static byte[] CF(byte[] V, byte[] B)
        {
            int[] v, b;
            v = convert(V);
            b = convert(B);

            return convert(CF(v, b));
        }

        private static int[] convert(byte[] arr)
        {
            int[] outData = new int[arr.Length / 4];
            byte[] tmp = new byte[4];
            for (int i = 0; i < arr.Length; i += 4)
            {
                System.Array.Copy(arr, i, tmp, 0, 4);
                outData[i / 4] = bigEndianByteToInt(tmp);
            }

            return outData;
        }

        private static byte[] convert(int[] arr)
        {
            byte[] outData = new byte[arr.Length * 4];
            byte[] tmp = null;
            for (int i = 0; i < arr.Length; i++)
            {
                tmp = bigEndianIntToByte(arr[i]);
                System.Array.Copy(tmp, 0, outData, i * 4, 4);
            }

            return outData;
        }

        public static int[] CF(int[] V, int[] B)
        {
            int a, b, c, d, e, f, g, h;
            int ss1, ss2, tt1, tt2;
            a = V[0];
            b = V[1];
            c = V[2];
            d = V[3];
            e = V[4];
            f = V[5];
            g = V[6];
            h = V[7];
            /*
             * System.out.print("  "); System.out.print(Integer.toHexString(a)+" ");
             * System.out.print(Integer.toHexString(b)+" ");
             * System.out.print(Integer.toHexString(c)+" ");
             * System.out.print(Integer.toHexString(d)+" ");
             * System.out.print(Integer.toHexString(e)+" ");
             * System.out.print(Integer.toHexString(f)+" ");
             * System.out.print(Integer.toHexString(g)+" ");
             * System.out.print(Integer.toHexString(h)+" "); System.out.println();
             */
            /*
             * System.out.println("block ..."); for(int i=0; i<B.length; i++) {
             * System.out.print(Integer.toHexString(B[i])+" "); }
             * System.out.println(); System.out.println("iv ..."); for(int i=0;
             * i<V.length; i++) { System.out.print(Integer.toHexString(V[i])+" "); }
             * System.out.println();
             */

            int[][] arr = expand(B);
            int[] w = arr[0];
            int[] w1 = arr[1];
            /*
             * System.out.println("W"); print(w); System.out.println("W1");
             * print(w1);
             */
            // System.out.println("---------------------------------------------------------");
            for (int j = 0; j < 64; j++)
            {
                ss1 = (bitCycleLeft(a, 12) + e + bitCycleLeft(Tj[j], j));
                ss1 = bitCycleLeft(ss1, 7);
                ss2 = ss1 ^ bitCycleLeft(a, 12);
                tt1 = FFj(a, b, c, j) + d + ss2 + w1[j];
                tt2 = GGj(e, f, g, j) + h + ss1 + w[j];
                d = c;
                c = bitCycleLeft(b, 9);
                b = a;
                a = tt1;
                h = g;
                g = bitCycleLeft(f, 19);
                f = e;
                e = P0(tt2);

                /*
                 * System.out.print(j+" ");
                 * System.out.print(Integer.toHexString(a)+" ");
                 * System.out.print(Integer.toHexString(b)+" ");
                 * System.out.print(Integer.toHexString(c)+" ");
                 * System.out.print(Integer.toHexString(d)+" ");
                 * System.out.print(Integer.toHexString(e)+" ");
                 * System.out.print(Integer.toHexString(f)+" ");
                 * System.out.print(Integer.toHexString(g)+" ");
                 * System.out.print(Integer.toHexString(h)+" ");
                 * System.out.println();
                 */
            }
            // System.out.println("*****************************************");

            int[] outData = new int[8];
            outData[0] = a ^ V[0];
            outData[1] = b ^ V[1];
            outData[2] = c ^ V[2];
            outData[3] = d ^ V[3];
            outData[4] = e ^ V[4];
            outData[5] = f ^ V[5];
            outData[6] = g ^ V[6];
            outData[7] = h ^ V[7];

            return outData;
        }

        private static int[][] expand(byte[] B)
        {
            // PrintUtil.printWithHex(B);
            int[] W = new int[68];
            int[] W1 = new int[64];
            byte[] tmp = new byte[4];
            for (int i = 0; i < B.Length; i += 4)
            {
                for (int j = 0; j < 4; j++)
                {
                    tmp[j] = B[i + j];
                }
                W[i / 4] = bigEndianByteToInt(tmp);
            }

            for (int i = 16; i < 68; i++)
            {
                W[i] = P1(W[i - 16] ^ W[i - 9] ^ bitCycleLeft(W[i - 3], 15)) ^ bitCycleLeft(W[i - 13], 7) ^ W[i - 6];
            }

            for (int i = 0; i < 64; i++)
            {
                W1[i] = W[i] ^ W[i + 4];
            }

            int[][] arr = new int[][] { W, W1 };

            return arr;
        }

        private static int[][] expand(int[] B)
        {
            int[] W = new int[68];
            int[] W1 = new int[64];
            for (int i = 0; i < B.Length; i++)
            {
                W[i] = B[i];
            }

            for (int i = 16; i < 68; i++)
            {
                W[i] = P1(W[i - 16] ^ W[i - 9] ^ bitCycleLeft(W[i - 3], 15)) ^ bitCycleLeft(W[i - 13], 7) ^ W[i - 6];
            }

            for (int i = 0; i < 64; i++)
            {
                W1[i] = W[i] ^ W[i + 4];
            }

            int[][] arr = new int[][] { W, W1 };

            return arr;
        }

        private static byte[] bigEndianIntToByte(int num)
        {
            return back(Util.IntToByte(num));
        }

        private static int bigEndianByteToInt(byte[] bytes)
        {
            return Util.ByteToInt(back(bytes));
        }

        private static int FFj(int X, int Y, int Z, int j)
        {
            if (j >= 0 && j <= 15)
            {
                return FF1j(X, Y, Z);
            }
            else
            {
                return FF2j(X, Y, Z);
            }
        }

        private static int GGj(int X, int Y, int Z, int j)
        {
            if (j >= 0 && j <= 15)
            {
                return GG1j(X, Y, Z);
            }
            else
            {
                return GG2j(X, Y, Z);
            }
        }

        /***********************************************/
        // 逻辑位运算函数
        private static int FF1j(int X, int Y, int Z)
        {
            int tmp = X ^ Y ^ Z;

            return tmp;
        }

        private static int FF2j(int X, int Y, int Z)
        {
            int tmp = ((X & Y) | (X & Z) | (Y & Z));

            return tmp;
        }

        private static int GG1j(int X, int Y, int Z)
        {
            int tmp = X ^ Y ^ Z;

            return tmp;
        }

        private static int GG2j(int X, int Y, int Z)
        {
            int tmp = (X & Y) | (~X & Z);

            return tmp;
        }

        private static int P0(int X)
        {
            int y = rotateLeft(X, 9);
            y = bitCycleLeft(X, 9);
            int z = rotateLeft(X, 17);
            z = bitCycleLeft(X, 17);
            int t = X ^ y ^ z;

            return t;
        }

        private static int P1(int X)
        {
            int t = X ^ bitCycleLeft(X, 15) ^ bitCycleLeft(X, 23);

            return t;
        }

        /**
         * 对最后一个分组字节数据padding
         * 
         * @param in
         * @param bLen
         *            分组个数
         * @return
         */
        public static byte[] padding(byte[] inData, int bLen)
        {
            // 第一bit为1 所以长度=8 * in.length+1 k为所补的bit k+1/8 为需要补的字节
            int k = 448 - (8 * inData.Length + 1) % 512;
            if (k < 0)
            {
                k = 960 - (8 * inData.Length + 1) % 512;
            }
            k += 1;
            byte[] padd = new byte[k / 8];
            padd[0] = (byte)0x80;
            long n = inData.Length * 8 + bLen * 512;
            // 64/8 字节 长度
            // k/8 字节padding
            byte[] outData = new byte[inData.Length + k / 8 + 64 / 8];
            int pos = 0;
            System.Array.Copy(inData, 0, outData, 0, inData.Length);
            pos += inData.Length;
            System.Array.Copy(padd, 0, outData, pos, padd.Length);
            pos += padd.Length;
            byte[] tmp = back(Util.LongToByte(n));
            System.Array.Copy(tmp, 0, outData, pos, tmp.Length);

            return outData;
        }

        /**
         * 字节数组逆序
         * 
         * @param in
         * @return
         */
        private static byte[] back(byte[] inData)
        {
            byte[] outData = new byte[inData.Length];
            for (int i = 0; i < outData.Length; i++)
            {
                outData[i] = inData[outData.Length - i - 1];
            }

            return outData;
        }

        public static int rotateLeft(int x, int n)
        {
            return (x << n) | (x >> (32 - n));
            // return (((x) << (n)) | ((x) >> (32-(n))));
        }

        private static int bitCycleLeft(int n, int bitLen)
        {
            bitLen %= 32;
            byte[] tmp = bigEndianIntToByte(n);
            int byteLen = bitLen / 8;
            int len = bitLen % 8;
            if (byteLen > 0)
            {
                tmp = byteCycleLeft(tmp, byteLen);
            }

            if (len > 0)
            {
                tmp = bitSmall8CycleLeft(tmp, len);
            }

            return bigEndianByteToInt(tmp);
        }

        private static byte[] bitSmall8CycleLeft(byte[] inData, int len)
        {
            byte[] tmp = new byte[inData.Length];
            int t1, t2, t3;
            for (int i = 0; i < tmp.Length; i++)
            {
                t1 = (byte)((inData[i] & 0x000000ff) << len);
                t2 = (byte)((inData[(i + 1) % tmp.Length] & 0x000000ff) >> (8 - len));
                t3 = (byte)(t1 | t2);
                tmp[i] = (byte)t3;
            }

            return tmp;
        }

        private static byte[] byteCycleLeft(byte[] inData, int byteLen)
        {
            byte[] tmp = new byte[inData.Length];
            System.Array.Copy(inData, byteLen, tmp, 0, inData.Length - byteLen);
            System.Array.Copy(inData, 0, tmp, inData.Length - byteLen, byteLen);

            return tmp;
        }

        //public static void main(String[] args) {

        //    SM3Digest sm3 = new SM3Digest();
        //    byte[] x = { (byte) 0xa5, (byte) 0x79, (byte) 0x7b, (byte) 0x61, (byte) 0x24, (byte) 0xd7, (byte) 0x6d, (byte) 0x4d, (byte) 0xdf, (byte) 0x09, (byte) 0xce, (byte) 0xb8, (byte) 0x1e,
        //            (byte) 0x7f, (byte) 0x13, (byte) 0xc2, (byte) 0xaa, (byte) 0x34, (byte) 0x78, (byte) 0xa8, (byte) 0x54, (byte) 0x74, (byte) 0xce, (byte) 0x21, (byte) 0x18, (byte) 0x93, (byte) 0xa9,
        //            (byte) 0x6f, (byte) 0x0c, (byte) 0x44, (byte) 0xac, (byte) 0xda };
        //    byte[] y = { (byte) 0x56, (byte) 0x93, (byte) 0xb0, (byte) 0x28, (byte) 0x69, (byte) 0xa4, (byte) 0x6d, (byte) 0x94, (byte) 0xe4, (byte) 0xc4, (byte) 0x80, (byte) 0xe0, (byte) 0xb7,
        //            (byte) 0xa4, (byte) 0x49, (byte) 0xc6, (byte) 0xae, (byte) 0x1a, (byte) 0xcf, (byte) 0xad, (byte) 0x55, (byte) 0x69, (byte) 0x89, (byte) 0x6d, (byte) 0x76, (byte) 0x84, (byte) 0xac,
        //            (byte) 0xef, (byte) 0xbe, (byte) 0x3a, (byte) 0xfa, (byte) 0xf2 };
        //    String s = "1111";
        //    byte[] sm2Za = sm3.getSM2Za(x, y, "1234567812345678".getBytes());
        //    sm3.update(sm2Za, 0, sm2Za.length);
        //    // printHexString(sm2Za);
        //    System.out.println("\n");
        //    byte[] p = s.getBytes();
        //    sm3.update(p, 0, p.length);
        //    // printHexString(p);
        //    System.out.println("\n");
        //    byte[] md = new byte[32];
        //    sm3.doFinal(md, 0);
        //}

        //public static void print(int[] arr) {
        //    for (int i = 0; i < arr.length; i++) {
        //        /*
        //         * System.out.print(PrintUtil.toHexString(back(ConvertUtil.IntToByte(
        //         * arr[i]))) + " "); if((i+1) % 8 == 0) { System.out.println(); }
        //         */
        //        System.out.print(Integer.toHexString(arr[i]) + " ");
        //        if ((i + 1) % 16 == 0) {
        //            System.out.println();
        //        }
        //    }
        //    System.out.println();
        //}
    }

    public class Util
    {
        private static BigInteger p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
        private static BigInteger a = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
        private static BigInteger b = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
        private static BigInteger n = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
        private static BigInteger Gx = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
        private static BigInteger Gy = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

        // private static BigInteger p = new BigInteger(
        // "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
        // 16);
        // private static BigInteger a = new BigInteger(
        // "FFFFFFFC00000003FFFFFFFFFFFFFFFCFFFFFFFF000000010000000000000001",
        // 16);
        // private static BigInteger b = new BigInteger(
        // "00000000000000000000000000000000FFFFFFFBFFFFFFFFFFFFFFFFFFFFFFFF",
        // 16);
        // private static BigInteger n = new BigInteger(
        // "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
        // 16);
        // private static BigInteger Gx = new BigInteger(
        // "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
        // 16);
        // private static BigInteger Gy = new BigInteger(
        // "FFFFFFFF00000000FFFFFFFFFFFFFFFCFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF",
        // 16);
        /*
         * private static BigInteger p = new
         * BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"
         * , 16); private static BigInteger a = new
         * BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
         * , 16); private static BigInteger b = new
         * BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
         * , 16); private static BigInteger n = new
         * BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"
         * , 16); private static BigInteger Gx = new
         * BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
         * , 16); private static BigInteger Gy = new
         * BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
         * , 16);
         */
        public static byte[] getP()
        {
            return asUnsigned32ByteArray(p);
        }

        public static byte[] getA()
        {
            return asUnsigned32ByteArray(a);
        }

        public static byte[] getB()
        {
            return asUnsigned32ByteArray(b);
        }

        public static byte[] getN()
        {
            return asUnsigned32ByteArray(n);
        }

        public static byte[] getGx()
        {
            return asUnsigned32ByteArray(Gx);
        }

        public static byte[] getGy()
        {
            return asUnsigned32ByteArray(Gy);
        }

        /*
         * static { System.out.println("p len = " + p.toByteArray().length);
         * System.out.println("a len = " + a.toByteArray().length);
         * System.out.println("b len = " + b.toByteArray().length);
         * System.out.println("n len = " + n.toByteArray().length);
         * System.out.println("Gx len = " + Gx.toByteArray().length);
         * System.out.println("Gy len = " + Gy.toByteArray().length); }
         */
        /**
         * 整形转换成网络传输的字节流（字节数组）型数据
         * 
         * @param num
         *            一个整型数据
         * @return 4个字节的自己数组
         */
        public static byte[] IntToByte(int num)
        {
            byte[] bytes = new byte[4];

            bytes[0] = (byte)(0xff & (num >> 0));
            bytes[1] = (byte)(0xff & (num >> 8));
            bytes[2] = (byte)(0xff & (num >> 16));
            bytes[3] = (byte)(0xff & (num >> 24));

            return bytes;
        }

        /**
         * 四个字节的字节数据转换成一个整形数据
         * 
         * @param bytes
         *            4个字节的字节数组
         * @return 一个整型数据
         */
        public static int ByteToInt(byte[] bytes)
        {
            int num = 0;
            int temp;
            temp = (0x000000ff & (bytes[0])) << 0;
            num = num | temp;
            temp = (0x000000ff & (bytes[1])) << 8;
            num = num | temp;
            temp = (0x000000ff & (bytes[2])) << 16;
            num = num | temp;
            temp = (0x000000ff & (bytes[3])) << 24;
            num = num | temp;

            return num;
        }

        public static byte[] LongToByte(long num)
        {
            byte[] bytes = new byte[8];

            for (int i = 0; i < 8; i++)
            {
                bytes[i] = (byte)(0xff & (num >> (i * 8)));
            }

            return bytes;
        }

        public static byte[] asUnsigned32ByteArray(BigInteger n)
        {
            return asUnsignedNByteArray(n, 32);
        }

        public static byte[] asUnsignedNByteArray(BigInteger x, int length)
        {
            if (x == null)
            {
                return null;
            }

            byte[] tmp = new byte[length];
            int len = x.ToByteArray().Length;
            if (len > length + 1)
            {
                return null;
            }

            if (len == length + 1)
            {
                if (x.ToByteArray()[0] != 0)
                {
                    return null;
                }
                else
                {
                    System.Array.Copy(x.ToByteArray(), 1, tmp, 0, length);
                    return tmp;
                }
            }
            else
            {
                System.Array.Copy(x.ToByteArray(), 0, tmp, length - len, len);
                return tmp;
            }

        }

        /**
         * 大数字转换字节流（字节数组）型数据
         * 
         * @param n
         * @return
         */
        public static byte[] byteConvert32Bytes(BigInteger n)
        {
            byte[] tmpd = null;
            if (n == null)
            {
                return null;
            }

            if (n.ToByteArray().Length == 33)
            {
                tmpd = new byte[32];
                System.Array.Copy(n.ToByteArray(), 1, tmpd, 0, 32);
            }
            else if (n.ToByteArray().Length == 32)
            {
                tmpd = n.ToByteArray();
            }
            else
            {
                tmpd = new byte[32];
                for (int i = 0; i < 32 - n.ToByteArray().Length; i++)
                {
                    tmpd[i] = 0;
                }
                System.Array.Copy(n.ToByteArray(), 0, tmpd, 32 - n.ToByteArray().Length, n.ToByteArray().Length);
            }
            return tmpd;
        }

    }
}