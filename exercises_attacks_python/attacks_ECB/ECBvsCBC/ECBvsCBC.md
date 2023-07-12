# ECBvsCBC attack walkthrough

Here we want to discover if the server is using a CBC or ECB mode of operation paired with AES.
The basic assuption is that 2 identical blocks will be entrypted in the same way if we are operating with ECB mode. On the contrary we assume that 2 identical blocks will be different in their ciphertext if we use CBC mode.

## Analysis

We can test the server and see what it returns as a result of our inputs. 
The server applies a basic prefix and a suffix so to fully control two blocks of data we need to be sure that the inilia padding after the prefix is filled.
As an exaple: 'prefixaaaaa aaaaaaaaaaa aaaaaaaaaaa aaaaasuffix'
Now we have two full blocks under our control and we can see if the server is using CBC or ECB