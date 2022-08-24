using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        int POWER(int xa, int xb, int q)
        {
            int Pow = 1;
            int i = 1;
            if (xb == 1)
            {
                return xa;
            }
            else
            {
                while (i <= xb)
                {
                    Pow *= xa;
                    Pow %= q;
                    i++;
                }
            }
            return Pow;
        }
        public static int YB, YA, Key_A, Key_B;
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> result = new List<int>();
            if (xa < q && xb < q)
            {
                YA = POWER(alpha, xa, q);
                YB = POWER(alpha, xb, q);
                Key_A = POWER(YB, xa, q);
                Key_B = POWER(YA, xb, q);
                if (Key_A == Key_B)
                {
                    result.Add(Key_A);
                    result.Add(Key_B);
                }
            }

            return result;
        }

    }
}
