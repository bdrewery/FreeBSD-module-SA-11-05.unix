This module checks the length of the sockaddr passed into bind(2) and connect(2) for proper length. This should address the SA-11:05.unix advisory.


# Usage
env PATH=/bin:/sbin:/usr/sbin:/usr/bin /bin/sh -c "make clean && make && make load"
