/*
    DataBridges C# NaCl wrapper for databridges library.
    https://www.databridges.io/


    Copyright 2022 Optomate Technologies Private Limited.

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

using System;
using System.Security.Cryptography;
using System.Text;
using NaCl;


namespace Databridges.NaCl.Wrapper
{


    public class DataBridges_NaCl_Wrapper
    {
        public String secret = "";

        public DataBridges_NaCl_Wrapper()
        {
            this.secret = "";
        }

        public String write(String message)
        {
       
                if (String.IsNullOrEmpty(this.secret)) { throw new dbnwError("INVALID_SECRET", "");  }
                if (String.IsNullOrEmpty(message)) {  throw new dbnwError("INVALID_DATA", "");  }
            try
            {
                byte[] secretKey = Encoding.UTF8.GetBytes(this.secret);
                byte[] m_message = Encoding.UTF8.GetBytes(message);
                var range = RandomNumberGenerator.Create();
                byte[] nonce = new byte[Curve25519XSalsa20Poly1305.NonceLength];
                range.GetBytes(nonce);
                using (XSalsa20Poly1305 secretBox = new XSalsa20Poly1305(secretKey))
                {
                    byte[] encrypteddBytes = new byte[message.Length + XSalsa20Poly1305.TagLength];
                    secretBox.Encrypt(encrypteddBytes, m_message, nonce);
                    String result = Encoding.UTF8.GetString(encrypteddBytes);
                    return Convert.ToBase64String(nonce) + ":" + Convert.ToBase64String(encrypteddBytes);
                }
            }
            catch (Exception e)
            {
                throw new dbnwError("NACL_EXCEPTION", e.Message);
            }
        }

        public string read(String data)
        {
            
                string decryptedText = null;
                byte[] cipher = null;
                byte[] nonce = null;

                if (String.IsNullOrEmpty(this.secret)) { throw new dbnwError("INVALID_SECRET", ""); }
                if (String.IsNullOrEmpty(data)) { throw new dbnwError("INVALID_DATA", ""); }

                String[] splitdata = data.Split(":".ToCharArray());
                if (splitdata.Length != 2) { throw new dbnwError("INVALID_DATA", ""); }

            try
            {
                cipher = Convert.FromBase64String(splitdata[1]);
                nonce = Convert.FromBase64String(splitdata[0]);

                byte[] secretKey = Encoding.UTF8.GetBytes(this.secret);
                using (XSalsa20Poly1305 secretBox = new XSalsa20Poly1305(secretKey))
                {
                    byte[] decryptedBytes = new byte[cipher.Length - XSalsa20Poly1305.TagLength];
                    if (secretBox.TryDecrypt(decryptedBytes, cipher, nonce))
                    {
                        decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                        return decryptedText;
                    }
                    else
                    {
                        return data;
                    }
                }
            }
            catch (Exception e)
            {
                throw new dbnwError("NACL_EXCEPTION", e.Message);
            }
        }
    }
}
