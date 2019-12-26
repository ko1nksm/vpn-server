#!/bin/bash -eux

export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn

chmod() { command chmod -v "$@"; }
curl() { command curl -sSLfv "$@"; }
install() { command install -Dv "$@"; }
ln() { command ln -nfv "$@"; }
mkdir() { command mkdir -pv "$@"; }

############################################################
# Report errors to Stackdriver Error Reporting
############################################################
set -o pipefail -o errtrace
error() {
  command="$BASH_COMMAND <$1>" tag="startup-script" stacktrace=""
  for ((i=1; i<${#BASH_SOURCE[@]}; i++)); do
    set -- "${BASH_SOURCE[$i]}" "${BASH_LINENO[$((i-1))]}" "${FUNCNAME[$i]}"
    stacktrace+=$'\n'"$1:$2:in \`$3'"
  done
  log="$command$stacktrace" message="${command//$'\n'/ }$stacktrace"
  logger -t "$tag" -p error <<< "$log"
  error-reporting "$tag" "$message"
}
trap '(set +x -- error: exit status $?; error $4)' ERR

############################################################
# Create error-reporting script
############################################################
install /dev/stdin /usr/local/bin/error-reporting << 'HERE'
#!/bin/bash -eu
# 1:<tag> 2:<message> 3:[functionName] 4:[filePath] 5:[lineNumber]
BS=$'\b' FF=$'\f' LF=$'\n' CR=$'\r' HT=$'\t'
tag=$1 message=$2 service=$(hostname) hash=$(uuidgen | sha1sum)
header=${message%%"$LF"*} && stacktrace=${message#"$header"}
header+="${header:+ }[${hash:0:10}]" && message="$header$stacktrace"
logger -t "$tag" -p error "$header"
shift 2 && set -- "$message" "$@"
for string in "$@"; do
  for trans in \\:\\ \":\" /:/ "$BS:b" "$FF:f" "$LF:n" "$CR:r" "$HT:t"; do
    string=${string//"${trans%%:*}"/"\\${trans#*:}"}
  done
  set -- "$@" "$string" && shift
done
payload='"serviceContext":{"service":"'$service'"},"message":"'$1'"'
if [ $# -ge 2 ]; then
  payload+=',"context":{"reportLocation":{"functionName":"'$2'"'
  payload+=${3+',"filePath":"'$3'"'}${4+',"lineNumber":"'$4'"'}'}}'
fi
set -- error-reporting "{$payload}"
gcloud logging write --severity=ERROR --payload-type=json "$@" 2>/dev/null
HERE

############################################################
# Setup for rsyslog
############################################################
install -m 644 /dev/stdin /etc/rsyslog.d/00-default.conf << 'HERE'
template(name="DefaultLogFormat" type="string"
  string="%timegenerated% %HOSTNAME% %syslogtag% [%syslogseverity-text%] %msg%\n"
)
$ActionFileDefaultTemplate DefaultLogFormat
HERE

install -m 644 /dev/stdin /etc/rsyslog.d/50-openvpn.conf << 'HERE'
:programname, isequal, "openvpn" -/var/log/openvpn.log
& stop
HERE

install -m 644 /dev/stdin /etc/rsyslog.d/50-ddclient.conf << 'HERE'
template(name="DDclientLogFormat" type="string"
  string="%timegenerated% %HOSTNAME% %syslogtag% [%syslogseverity-text%] %!msg%\n"
)
if $programname == "ddclient" then {
  set $!msg = $msg;
  set $!pass = re_extract($msg,'(password|pass|pw|token|tkn)=([^&]+)',0,2,"");
  if $!pass then set $!msg = replace($!msg, $!pass, "****"); # mask password
  action(type="omfile" template="DDclientLogFormat" File="/var/log/ddclient.log")
  stop
}
HERE

install -m 644 /dev/stdin /etc/rsyslog.d/50-httpd.conf << 'HERE'
:programname, isequal, "httpd" -/var/log/httpd.log
& stop
HERE

systemctl restart rsyslog

############################################################
# Install some useful tools
############################################################
apt-get update
apt-get install -y less tree

############################################################
# Install Stackdriver Logging agent
############################################################
if dpkg -s google-fluentd; then
  apt-get install -y --only-upgrade google-fluentd
else
  curl -O https://dl.google.com/cloudagents/install-logging-agent.sh
  DO_NOT_INSTALL_CATCH_ALL_CONFIG=1 bash install-logging-agent.sh --structured
fi

############################################################
# Setup for Stackdriver Logging
############################################################
time="(?<time>[^ ]* {1,2}[^ ]* [^ ]*)"
host="(?<host>[^ ]*)"
ident="(?<ident>[a-zA-Z0-9_\/\.\-]*)"
pid="(?<pid>[0-9]+)"
priority="(\[(?<severity>(emerg|alert|crit|err|warning|notice|info|debug))\] )"
severity_list="DEFAULT|DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY"
severity="((?<severity>($severity_list)) )"
message="(?<message>($severity?.*))"
syslog="^$time $host $ident(?:\[$pid\])?(?:[^\:]*\:)? *$priority? *$message$"

install -m 644 /dev/stdin /etc/google-fluentd/config.d/syslog.conf << HERE
<source>
  @type tail
  <parse>
    @type regexp
    expression /$syslog/
    time_format "%b %d %H:%M:%S"
  </parse>
  path /var/log/syslog
  pos_file /var/lib/google-fluentd/pos/syslog.pos
  read_from_head true
  tag syslog
</source>
HERE

install -m 644 /dev/stdin /etc/google-fluentd/config.d/syslog_endpoint.conf << HERE
<source>
  @type syslog
  port 514
  <transport udp>
  </transport>
  bind 127.0.0.1
  format /$message/
  tag syslog
</source>
<source>
  @type syslog
  port 514
  <transport tcp>
  </transport>
  bind 127.0.0.1
  format /$message/
  tag syslog
</source>
HERE

install -m 644 /dev/stdin /etc/google-fluentd/config.d/forward.conf << HERE
<source>
  @type forward
  # default port
  port 24224
  # only accept connections from localhost - to open this up, change to 0.0.0.0
  bind 127.0.0.1
</source>
HERE

install -m 644 /dev/stdin /etc/google-fluentd/config.d/ddclient.conf << HERE
<source>
  @type tail
  <parse>
    @type regexp
    expression /$syslog/
    time_format "%b %d %H:%M:%S"
  </parse>
  path /var/log/ddclient.log
  pos_file /var/lib/google-fluentd/pos/ddclient.pos
  read_from_head true
  tag ddclient
</source>
HERE
touch /var/log/ddclient.log

install -m 644 /dev/stdin /etc/google-fluentd/config.d/openvpn.conf << HERE
<source>
  @type tail
  <parse>
    @type regexp
    expression /$syslog/
    time_format "%b %d %H:%M:%S"
  </parse>
  path /var/log/openvpn.log
  pos_file /var/lib/google-fluentd/pos/openvpn.pos
  read_from_head true
  tag openvpn
</source>
HERE
touch /var/log/openvpn.log

install -m 644 /dev/stdin /etc/google-fluentd/config.d/httpd.conf << HERE
<source>
  @type tail
  <parse>
    @type regexp
    expression /$syslog/
    time_format "%b %d %H:%M:%S"
  </parse>
  path /var/log/httpd.log
  pos_file /var/lib/google-fluentd/pos/httpd.pos
  read_from_head true
  tag httpd
</source>
HERE
touch /var/log/httpd.log

mkdir /var/lib/google-fluentd/pos
systemctl disable google-fluentd
systemctl restart google-fluentd --no-block

############################################################
# Setup for logrotate
############################################################
install -m 644 /dev/stdin /etc/logrotate.d/openvpn << 'HERE'
/var/log/openvpn.log {
  daily rotate 30
  missingok
  notifempty
  delaycompress
  compress
  copytruncate
}
HERE

install -m 644 /dev/stdin /etc/logrotate.d/httpd << 'HERE'
/var/log/httpd.log {
  daily rotate 30
  missingok
  notifempty
  delaycompress
  compress
  copytruncate
}
HERE

############################################################
# Install Stackdriver Monitoring
############################################################
if dpkg -s stackdriver-agent; then
  apt-get install -y --only-upgrade stackdriver-agent
else
  curl -O https://dl.google.com/cloudagents/install-monitoring-agent.sh
  bash install-monitoring-agent.sh
fi

############################################################
# Setup for Stackdriver Monitoring
############################################################
install /dev/stdin /usr/local/share/openvpn/metrics.sh << 'HERE'
#!/bin/sh -eu
interval=${COLLECTD_INTERVAL:-60}
hostname=${COLLECTD_HOSTNAME:-$(hostname)}
status_log="/run/openvpn-server/status-server.log"
prefix="$hostname/exec-openvpn"

list_clients() { awk -F, '/^CLIENT_LIST/{print $2" "$6" "$7}' "$1"; }

while :; do
  [ -f "$status_log" ] && list_clients "$status_log" | {
    count=0
    while read -r name recieved sent; do
      # https://collectd.org/documentation/manpages/collectd-exec.5.shtml
      # PUTVAL Identifier [OptionList] Valuelist
      # Identifier: <host>/<plugin>-<plugin_instance>/<type>-<type_instance>
      # Type: See /opt/stackdriver/collectd/share/collectd/types.db
      echo "PUTVAL $prefix/if_rx_octets-$name interval=$interval N:$recieved"
      echo "PUTVAL $prefix/if_tx_octets-$name interval=$interval N:$sent"
      count=$((count+1))
    done
    echo "PUTVAL $prefix/current_sessions interval=$interval N:$count"
  }
  sleep "$interval"
done
HERE

install -m 644 /dev/stdin /etc/stackdriver/collectd.d/openvpn.conf << HERE
<Plugin "exec">
  Exec "nobody" "/usr/local/share/openvpn/metrics.sh"
</Plugin>
LoadPlugin target_set
PreCacheChain "PreCache"
<Chain "PreCache">
  <Rule "openvpn">
    <Match regex>
      Plugin "^exec$"
      PluginInstance "^openvpn$"
    </Match>
    <Target "set">
      MetaData "stackdriver_metric_type" "custom.googleapis.com/openvpn/%{type}"
      MetaData "label:name" "%{type}"
    </Target>
  </Rule>
  <Rule "openvpn_with_type_instance">
    <Match regex>
      Plugin "^exec$"
      PluginInstance "^openvpn$"
      TypeInstance "^.+$"
    </Match>
    <Target "set">
      MetaData "label:name" "%{type_instance} %{type}"
    </Target>
  </Rule>
</Chain>
HERE

systemctl restart stackdriver-agent --no-block

############################################################
# Create metadata script
############################################################
install /dev/stdin /usr/local/bin/metadata << 'HERE'
#!/bin/sh -eu
type=instance
case ${1:-} in (-p | --project) type=project; shift; esac
case ${1:-} in
  /*)  set -- "metadata/computeMetadata/v1/$type$@" ;;
  *) set -- "metadata/computeMetadata/v1/$type/attributes/$@" ;;
esac
data=$(curl -sSfH "Metadata-Flavor: Google" "$@")
printf '%s\n' "$data"
HERE

############################################################
# Retrive configuration
############################################################
bucket=$(metadata configuration-bucket)
edit_mode=$(metadata edit-mode)
mkdir /data
if [ "$edit_mode" = "true" ]; then
  if ! dpkg -s gcsfuse; then
    GCSFUSE_REPO=gcsfuse-$(lsb_release -c -s)
    gcsfuse="deb http://packages.cloud.google.com/apt $GCSFUSE_REPO main"
    echo "$gcsfuse" | tee /etc/apt/sources.list.d/gcsfuse.list
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
    apt-get update
  fi
  apt-get install -y gcsfuse
  gcsfuse "$bucket" /data
else
  mkdir /tmp/data
  (umask 0077; gsutil -m cp -r "gs://$bucket"/* /tmp/data)
  mount --bind /tmp/data /data
fi

############################################################
# Unit File for notify-failure.service
############################################################
install -m 644 /dev/stdin /etc/systemd/system/notify-failure@.service << 'HERE'
[Service]
Type=oneshot
# TODO: Use %j instead of %p in the future
Environment="p=%p"
ExecStart=/bin/sh -c 'error-reporting "$${p##*-}" "%i failed" "$${p##*-}" "%i"'
HERE
systemctl daemon-reload

############################################################
# Install DDclient
############################################################
apt-get install -y perl libio-socket-ssl-perl libdata-validate-ip-perl libjson-any-perl
ddclient=$(metadata ddclient)
curl "$ddclient" | tar zxv --one-top-level=/tmp/ddclient --strip-components 1
install /tmp/ddclient/ddclient /usr/local/sbin
mkdir /data/ddclient
ln -s /data/ddclient /etc/ddclient

ln /etc/systemd/system/notify-failure{,-ddclient}@.service

install -m 644 /dev/stdin /etc/systemd/system/ddclient.service << 'HERE'
[Unit]
Description=DDclient (oneshot)
OnFailure=notify-failure-ddclient@%n.service
[Service]
Type=oneshot
Environment="CONF=/etc/ddclient/ddclient.conf"
Environment="CACHE=/var/cache/ddclient.cache"
ExecStart=/usr/local/sbin/ddclient -foreground -force -verbose -file "$CONF" -cache "$CACHE"
HERE

ddns_update_interval=$(metadata ddns-update-interval)

install -m 644 /dev/stdin /etc/systemd/system/ddclient.timer << HERE
[Unit]
Description=Run DDclient periodically
[Timer]
OnActiveSec=0
${ddns_update_interval:+OnUnitActiveSec=$ddns_update_interval}
[Install]
WantedBy=timers.target
HERE

systemctl daemon-reload
if [ -e /etc/ddclient/ddclient.conf ]; then
  systemctl restart ddclient.timer
fi

############################################################
# Unit File for busybox httpd
############################################################
ln -s /bin/busybox /usr/local/bin/httpd

ln /etc/systemd/system/notify-failure{,-httpd}@.service

install -m 644 /dev/stdin /etc/systemd/system/httpd@.service << 'HERE'
[Unit]
Description=httpd server for %I
OnFailure=notify-failure-httpd@%n.service
[Service]
Type=simple
PIDFile=/var/run/httpd-%i.pid
Environment="DOCUMENT_ROOT=/var/www/%i"
Environment="CONF=/etc/httpd-%i.conf"
EnvironmentFile=/etc/default/httpd-%i
ExecStart=/usr/local/bin/httpd -f -v -h "$DOCUMENT_ROOT" -p "$IP" -c "$CONF"
ExecStartPost=/bin/sh -c 'echo $MAINPID > /var/run/httpd-%i.pid'
HERE

############################################################
# OpenVPN Status
############################################################
install -m 644 /dev/stdin /var/www/public/index.html.tmpl << 'HERE'
<!DOCTYPE html>
<html>
  <head><title>OpenVPN Status</title>
  <style>
  iframe {
    border: 0; width: 100%; height: 100%;
    position: absolute; top: 0; left: 0; right: 0; bottom: 0;
  }
  </style>
  </head>
  <body><iframe src="http://$IP/"></iframe></body>
</html>
HERE

install /dev/stdin /usr/local/share/openvpn/up.sh << 'HERE'
#!/bin/sh -eu
IP=$4 envsubst < /var/www/public/index.html.tmpl > /var/www/public/index.html
echo > /etc/httpd-private.conf
echo "IP=$4" > /etc/default/httpd-private
systemctl start httpd@private.service
HERE

install /dev/stdin /usr/local/share/openvpn/down.sh << 'HERE'
#!/bin/sh -eu
systemctl stop httpd@private.service
HERE

install /dev/stdin /var/www/private/cgi-bin/index.cgi << 'HERE'
#!/bin/sh -eu
status_log="/run/openvpn-server/status-server.log" res="200 OK" body=""
allow_status_page=$(metadata allow-status-page)
if [ "$allow_status_page" = "true" ]; then
  [ -f "$status_log" ] && body=$(cat "$status_log") || res="404 Not Found"
else
  res="403 Forbidden"
fi
set -- "$res" "${body:-$res}"
printf 'HTTP/1.1 %s\r\nContent-type: text/plain\r\n\r\n%s' "$@"
HERE

install /dev/stdin /usr/local/bin/update-anti-robot-auth << 'HERE'
#!/bin/sh -eu
metadata() {
  set -- "metadata/computeMetadata/v1/instance/attributes/$@"
  busybox wget -q -O - --header "Metadata-Flavor: Google" "$@"
}
loop=1
while sleep 1 && [ "$loop" ] && loop=${2:+1}; do
  auth=$(metadata "anti-robot-auth${2:+?wait_for_change=true&timeout_sec=1800}")
  echo "/:$auth" | cmp -s "$1" && continue
  echo "/:$auth" > "$1"
  logger -t httpd "Update anti-robot-auth: $auth"
  pid=$(cat "${2:-/dev/null}" 2>/dev/null) ||:
  [ "$pid" ] || continue
  logger -t httpd "Reload $1" >&2
  kill -HUP "$pid" 2>/dev/null ||:
done
HERE

install -m 644 /dev/stdin /etc/systemd/system/update-anti-robot-auth.service << 'HERE'
[Unit]
Description=Update anti robot auth
OnFailure=notify-failure-syslog@%n.service
[Service]
Type=simple
Environment="CONF=/etc/httpd-public.conf"
Environment="PIDFILE=/var/run/httpd-public.pid"
ExecStart=/usr/local/bin/update-anti-robot-auth "$CONF" "$PIDFILE"
HERE

update-anti-robot-auth /etc/httpd-public.conf
echo "IP=$(hostname -i)" | tee /etc/default/httpd-public

systemctl daemon-reload
systemctl start httpd@public.service update-anti-robot-auth.service --no-block

############################################################
# Install OpenVPN
############################################################
apt-get install -y -t stretch-backports --no-install-recommends openvpn
install -m 644 /dev/null /run/openvpn-server/status-server.log
chmod 755 /run/openvpn-server
mkdir /data/openvpn
mount --bind /data/openvpn /etc/openvpn/server

ln /etc/systemd/system/notify-failure{,-openvpn}@.service

install -m 644 /dev/stdin /etc/systemd/system/openvpn-server@.service.d/override.conf << 'HERE'
[Unit]
OnFailure=notify-failure-openvpn@%n.service
StartLimitIntervalSec=5min
StartLimitBurst=5
[Service]
Restart=on-failure
RestartSec=30s
HERE

systemctl daemon-reload
systemctl disable openvpn.service openvpn-server@server.service
if [ -e /etc/openvpn/server/server.conf ]; then
  systemctl restart openvpn-server@server.service --no-block
fi

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
if metadata instance-template >/dev/null 2>&1; then
  systemctl start httpd@healthcheck.service --no-block
fi
