# CopyPaste attack walkthrough

Here we have the souce code of the server that is performing some operations with the session cookie.

Looking at the code (it is a silly example) we can see that the server is only checking the admin role and nothing else. If we are able to forge a cookie that has an 'admin' role we would get access to the resources that the server is offering.

The cookie is encrypted with a key K and we don't know it. We know that the server is using ECB and so we try to perform the CopyPaste attack against ECB.

## Analysis

As user we can control the input that we send to the cookie service, we have to pay attention to the allignment.

### Step 1

We know that the cookie service is creating the cookie with a specific format that we cannot control, specifically it creates the cookie starting from our input: the email.
To start the attack we can send an email address big enough to force the '&role=' to be the last element of a block. 

### Step 2 

Now we can send another input this time with an email address of this form: 'aaaaaaaa admin' and forcing it to allign the 'admin' part of the email to the beginning of the new block


### Step 3

We combine the first output (minus the last block) that gave us the initial elements of the cookie, with the last output (just the last block) which gave us the encrypted string containing the admin role

