# one-time-pad

A small suite of executables to facilitate encryption and decryption of uppercase alphabetical messages of varying lengths. Includes a keygen program to create a cipher of the specified length, two programs that run as servers and listen for connections before accepting and encoding / decoding the provided message using the provided cipher, and two client programs that connect to the aforementioned servers to send / receive messages.

## Compile
Run 'compileall' using ./compileall (may need to use chmod first).

## Usage

### keygen
keygen <length>

### otp_enc_d
otp_enc_d \<port\>

### otp_enc
otp_enc \<text filename\> \<key filename\> \<port\>

### otp_dec_d
otp_dec_d \<port\>

### otp_dec
otp_dec \<cipher filename\> \<key filename\> \<port\>


## Notes:
The otp_enc and otp_dec programs output to stdout, so in order to get a file to pass to the respective program, output needs to be redirected.
