using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string alphabet = "abcdefghijklmnopqrstuvwxyz";
        public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();
            char[] input = plainText.ToCharArray();
            int first = 'a';
            for (int i = 0; i < input.Length; i++)
            {
                char indexofch = input[i];
                int old = indexofch - first;
                int newind = (old + key) % 26;
                char newcharindx = (char)(first + newind);
                input[i] = newcharindx;
            }
            return new string(input);
        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            char[] input1 = cipherText.ToCharArray();
            int first = 'A';
            int newindex2;
            for (int i = 0; i < input1.Length; i++)
            {
                char indexofch = input1[i];//k=107
                int old = indexofch - first; //107-97=10
                int newind = (old - key);//2-8=-6
                if (newind > 0 && newind < 26)
                {
                    newindex2 = newind % 26;
                }
                else if (newind > 26)
                {

                    newindex2 = (newind - 26) % 26;
                }
                else
                {
                    newindex2 = (newind + 26) % 26;
                }
                char newcharindx = (char)(newindex2 + first);
                input1[i] = newcharindx;
            }
            return new string(input1);
        }

        public int Analyse(string plainText, string cipherText)
        {
            //  throw new NotImplementedException();
            char[] input1 = plainText.ToCharArray();
            char[] input2 = cipherText.ToCharArray();
            int first1 = 'a';
            int first2 = 'A';

            int i = 0;
            char PlainTextch1 = input1[i];//c
            char cipherTextch1 = input2[i];//k
            int oldplain1 = PlainTextch1 - first1;//99-97=2=c
            int oldcipher2 = cipherTextch1 - first2;//107-97=10=k
            int key = oldcipher2 - oldplain1;
            if (key < 0)
            {
                key += 26;
            }
            return key;

        }
    }
}
