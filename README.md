# one-time-pad

Compile
Run 'compileall' using ./compileall (may need to use chmod first).

OTP_DEC_D
USAGE: otp_dec_d <port>

OTP_ENC_D
USAGE: otp_enc_d <port>

OTP_DEC
USAGE: otp_dec <cipher filename> <key filename> <port>

OTP_ENC
USAGE: otp_enc <text filename> <key filename> <port>

#misc:
The otp_enc and otp_dec programs output to stdout, so in order to get a file to pass to the respective program, output needs to be redirected.
