using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using SM2Crypto.Lib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SM2Crypto
{
    class Program
    {
        private static  string PubKey= "041E353292615666BB47F6358D3E893394D34AF30D64875E2E422182C15885D3ECA697C345EED99268D3CAC5F6054780C34433E1BF12EBFF1F744B67A2F6863CFB";
        private static  string PriKey = "00FAB34B54C026D158B54C88BC0463CB79B22661C7C870AD2A0455300E05471CE1";


        static void Main(string[] args)
        {

            //byte a = 149;
            //var a1 = Hex.Encode(new byte[] { a });
            //var b = Hex.Decode(a1);

            //生成公钥私钥对
            TestSm2GetKeyPair();

            //test
            TestSm2Enc();

            Console.WriteLine("finish work");
            Console.ReadKey();
        }

        public static void TestSm2GetKeyPair()
        {
            SM2Utils sm2Utils = new SM2Utils();
            ECPoint pubk;
            BigInteger prik;
            SM2Utils.GenerateKeyPair( out pubk,  out prik);
            PubKey = Encoding.ASCII.GetString(Hex.Encode(pubk.GetEncoded())).ToUpper();
            PriKey = Encoding.ASCII.GetString(Hex.Encode(prik.ToByteArray())).ToUpper();
            //System.Console.Out.WriteLine("公钥: " + Encoding.ASCII.GetString(Hex.Encode(publicKey.GetEncoded())).ToUpper());
            //System.Console.Out.WriteLine("私钥: " + Encoding.ASCII.GetString(Hex.Encode(privateKey.ToByteArray())).ToUpper());
        }


        public static  void TestSm2Enc()
        {
            string testStr = "hello world";
            Console.WriteLine("原始数据 : " + testStr);
            byte[] sourceData = Encoding.ASCII.GetBytes(testStr);
            byte[] pubk = Encoding.ASCII.GetBytes(PubKey);
            string encStr =  SM2Utils.Encrypt(Hex.Decode(pubk), sourceData);

            Console.WriteLine("加密后数据 : " + encStr);

            byte[] prik = Encoding.ASCII.GetBytes(PriKey);
            var data =Hex.Decode(Encoding.ASCII.GetBytes(encStr));
            var decodedData = SM2Utils.Decrypt(Hex.Decode(prik), data);

            var decodedStr = Encoding.ASCII.GetString(decodedData);
            Console.WriteLine("解密后数据 : " + decodedStr);
        }
    }
}
