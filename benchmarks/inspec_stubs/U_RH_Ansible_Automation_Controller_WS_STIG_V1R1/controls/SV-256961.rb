control 'SV-256961' do
  title 'The Automation Controller NGINX web server application, libraries, and configuration files must only be accessible to privileged users.'
  desc 'Automation Controller NGINX web servers can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to Automation Controller NGINX web servers and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.'
  desc 'check', 'As a System Administrator for each Automation Controller NGINX web server host, check that the file permissions for the web server components require privileged access:

$ [ `find /etc/nginx -type f -not -perm 644 | wc -l` -gt 0 ] && echo "FAILED"

If "FAILED" is displayed, this is a finding.'
  desc 'fix', 'As a System Administrator for each Automation Controller NGINX web server host, modify the file permissions for the web server components require privileged access:

chmod -R 644 /etc/nginx && chown -R nginx /etc/nginx'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60636r902395_chk'
  tag severity: 'medium'
  tag gid: 'V-256961'
  tag rid: 'SV-256961r902397_rule'
  tag stig_id: 'APWS-AT-000780'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag fix_id: 'F-60578r902396_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
