# basicauth
A Go "net/http"-compatible Basic Authentication middleware

This is an opinionated library that assumes you have stored bcrypt-hashed
passwords for your users. In addition, to keep this library performant, it is
currently configured for passwords encrypted using bcrypt.MinCost. I'll make
this configurable at some point, but increasing from bcrypt.MinCost (4) to 8
increases the execution time of the handler from 1ms to 25ms according to the
benchmark.
