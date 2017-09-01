# one-time-pad

## Compile
Run 'compileall' using ./compileall (may need to use chmod first).

## Usage
### otp_enc_d
otp_enc_d <port>

### otp_enc
otp_enc <text filename> <key filename> <port>

### otp_dec_d
otp_dec_d <port>

### otp_dec
otp_dec <cipher filename> <key filename> <port>


## Notes:
The otp_enc and otp_dec programs output to stdout, so in order to get a file to pass to the respective program, output needs to be redirected.
