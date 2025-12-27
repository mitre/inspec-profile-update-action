control 'SV-256962' do
  title 'The Automation Controller NGINX web server must be protected from being stopped by a nonprivileged user.'
  desc 'An attacker has at least two reasons to stop an Automation Controller NGINX web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to an Automation Controller NGINX web server configuration.

To prohibit an attacker from stopping the Automation Controller NGINX web server, the process ID (PID) of the web server and the utilities used to start/stop the web server must be protected from access by nonprivileged users. By knowing the PID and having access to the Automation Controller NGINX web server utilities, a nonprivileged user has a greater capability of stopping the server, whether intentionally or unintentionally.'
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server host, verify required service definition is protected from unprivileged users:

stat -c "%a %U %G" /usr/lib/systemd/system/automation-controller.service | grep -q "644 root root" || echo "FAILED"
stat -c "%a %U %G" /usr/lib/systemd/system/supervisord.service | grep -q "644 root root" || echo "FAILED"
stat -c "%a %U %G"  /usr/lib/systemd/system/nginx.service | grep -q "644 root root" || echo "FAILED"

If "FAILED" is displayed, this is a finding.

Verify the required services are enabled:

systemctl is-enabled automation-controller.service >/dev/null || echo FAILED
systemctl is-enabled supervisord.service >/dev/null || echo FAILED
systemctl is-enabled nginx.service >/dev/null || echo FAILED

If "FAILED" is displayed, this is a finding.

Verify application services are correctly managed by supervisord. Verify protection of and capture supervisord configuration.

stat -c "%a %U %G" /etc/supervisord.d/*.ini | grep -q "644 root root" || echo "FAILED"
cat  /etc/supervisord.d/*.ini | sed -n -E "/^\[.*\]/{s/\[(.*)\]/\1/;h;n;};/^[a-zA-Z]/{s/#.*//;G;s/([^ ]*) *= *(.*)\n(.*)/\3_\1='\2'/;p;}" > /tmp/supervisord.parsed.conf

Verify specific start and restart properties for application services:

application_services=(program:awx-dispatcher_autostart program:awx-dispatcher_autorestart program:awx-wsbroadcast_autostart program:awx-wsbroadcast_autorestart program:awx-uwsgi_autostart program:awx-uwsgi_autorestart program:awx-daphne_autostart program:awx-daphne_autorestart program:awx-rsyslogd_autostart program:awx-rsyslogd_autorestart) 
for SUPERVISOR_CHECK in ${application_services[@]}; do grep $SUPERVISOR_CHECK /tmp/supervisord.parsed.conf | grep -q true || echo "FAILED" ; done
rm /tmp/supervisord.parsed.conf

If "FAILED" is displayed, this is a finding.)
  desc 'fix', 'As a System Administrator for each Automation Controller NGINX web server host, set the permissions correctly on the nginx service file:

sudo chown root:root /usr/lib/systemd/system/nginx.service
sudo chmod 644 /usr/lib/systemd/system/nginx.service

Reset the Ansible Automation Platform configuration to the defaults, which meet the requirements for the supervisord and automation-controller services.

Locate the inventory file used to install Ansible Automation Platform (usually in the installer directory).

Run the setup.sh command in the installer directory to reconfigure the controller to use the new setting:

sudo ./setup.sh'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60637r903550_chk'
  tag severity: 'medium'
  tag gid: 'V-256962'
  tag rid: 'SV-256962r903550_rule'
  tag stig_id: 'APWS-AT-000830'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-60579r902399_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
