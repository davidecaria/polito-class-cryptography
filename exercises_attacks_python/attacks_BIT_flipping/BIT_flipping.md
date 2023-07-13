# BIT Flipping attack walkthrough

This class of attacks is very powerful and have many variants depending on the victim specific configuration. There are two main categories depending on the type of cipher that we look at:
stream cipher or block cipher.
The goal of this attack is to modify the ciphertext without knowing the key

## Stream cipher

What makes this cipher vulnerable to this attack is the fact that the basic stream cipher performs the encryption vertically. 
We can force very small (and localized) changes in the inputs, resulting in a change in the output. To do so we can leverage a mask

## Block cipher

### ECB

With ECB mode it is not possible to perform this attack since small (and localized) change on one block is spread accross the entire length of the block.

### CBC

Here we can leverage the structure of CBC and still have a partial attack surface given by the fact that we can modify the n-1 block and have some influence on the n block. 
This happens because when we modify the n-1 block we will influence the next encryption thanks to the XOR operation performed at the next iteration. However, since we are modifying the n-1 block, its ciphertext will be compromized.