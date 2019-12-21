#!/bin/bash -eux

############################################################
# Health check
############################################################
install /dev/stdin /var/www/healthcheck/cgi-bin/index.cgi << 'HERE'
#!/bin/sh -eu
status_log="/run/openvpn-server/status-server.log"
res="503 Service Unavailable"
[ "$(find "$status_log" -mmin -1)" ] && res="200 OK"
printf 'HTTP/1.1 %s\r\nContent-type: text/plain\r\n\r\n%s' "$res" "$res"
HERE

cp /dev/null /etc/httpd-healthcheck.conf
echo "IP=8080" | tee /etc/default/httpd-healthcheck
systemctl start httpd@healthcheck.service
