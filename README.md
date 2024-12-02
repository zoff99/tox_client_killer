# Tox Client Killer



```
gcc -g -O2 tox_client_killer.c toxcore_amalgamation.c -o tox_client_killer \
 -I. $(pkg-config --libs --cflags opus) \
 $(pkg-config --libs --cflags libsodium vpx x264 libavcodec libavutil)

./tox_client_killer <ToxID to pound with random stuff>
```


<br>
Any use of this project's code by GitHub Copilot, past or present, is done
without our permission.  We do not consent to GitHub's use of this project's
code in Copilot.
<br>
No part of this work may be used or reproduced in any manner for the purpose of training artificial intelligence technologies or systems.
