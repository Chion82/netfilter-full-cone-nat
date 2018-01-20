:POSTROUTING
*nat
-j FULLCONENAT;=;OK
-j FULLCONENAT --random;=;OK
-j FULLCONENAT --random-fully;=;OK
-p tcp -j FULLCONENAT --to-ports 1024;=;OK
-p udp -j FULLCONENAT --to-ports 1024-65535;=;OK
-p udp -j FULLCONENAT --to-ports 1024-65536;;FAIL
-p udp -j FULLCONENAT --to-ports -1;;FAIL
