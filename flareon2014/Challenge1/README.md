# Challenge1.exe

The first challenge involves dumping out the challenge binary from the installation. Opening the installer with 7z, we extract `Challenge1.exe`.

Running `file`, we get the following:

``` Challenge1.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows```

We find that the executable is a .NET program. We use dotPeek from JetBrains to decompile the program. 


On decompiling, we get the following code:

```
 private void btnDecode_Click(object sender, EventArgs e)
    {
      this.pbRoge.Image = (Image) Resources.bob_roge;
      byte[] datSecret = Resources.dat_secret;
      string str1 = "";
      for (int index = 0; index < datSecret.Length; ++index)
      {
        byte num = datSecret[index];
        str1 += (string) (object) (char) (((int) num >> 4 | (int) num << 4 & 240) ^ 41);
      }
      string str2 = str1 + "\0";
      string str3 = "";
      for (int index = 0; index < str2.Length; index += 2)
        str3 = str3 + (object) str2[index + 1] + (object) str2[index];
      string str4 = "";
      for (int index = 0; index < str3.Length; ++index)
      {
        int num = (int) str3[index];
        str4 += (string) (object) (char) ((uint) (byte) str3[index] ^ 102U);
      }
      this.lbl_title.Text = str4;
    }
```

_Sidenote: I couldn't run the program so I didn't bother to verify what it was actually doing_

We see that `Resources.bob_roge` is completely unused so we ignore the value. We see a `Resources.dat_secret` that is used, and it's pretty safe to assume the secret is stored there, which we extract from the resources tab in dotPeek. The file contents are encoded, but the decoding is trivially reproducible in Python, as below:

```
f = open('rev_challenge_1.dat_secret.encode', 'rb')
for c in data:
    str1 += chr(((ord(c) >> 4 |  ord(c) << 4 & 240) ^ 41))
```

Printing `str1`, we get the flag.

``` 
In [5]: str1
Out[5]: '3rmahg3rd.b0b.d0ge@flare-on.com'
```


