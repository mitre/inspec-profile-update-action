control 'SV-256960' do
  title 'Nonprivileged accounts on the hosting system must only access Automation Controller NGINX web server security-relevant information and functions through a distinct administrative account.'
  desc 'It is important that Automation Controller NGINX web server security features are separated from nonprivileged users. Special “privileged” roles need to be developed so that only they can have access to those features and administer the web server, when necessary. These privileged roles will be better trained in the security features and will limit loss of data for forensic analysis and limits accidental changes to the web server.

Without isolating privileged users from nonprivileged users when administering to the web server, organizations run the risk of having limited access to forensic data, as well as increased risk of accidental changes, by nonprivileged and presumably less-trained individuals.

'
  desc 'check', %q(As a system administrator, for each Automation Controller NGINX web server host, inspect the current permissions and owner of Tower's web server configuration directory:

stat -c "%a %U %G" /etc/nginx | grep -q "755 root root" || echo "FAILED"
stat -c "%a %U %G" /etc/nginx/conf.d | grep -q "755 root root" || echo "FAILED"
stat -c "%a %U %G" /etc/nginx/nginx.conf | grep -q "644 root root" || echo "FAILED"
 
If "FAILED" is displayed, this is a finding.

Inspect the current permissions and owner of Automation Controller web server program configuration files:

stat -c "%a %U %G" /usr/lib/systemd/system/nginx.service | grep -q "644 root root" || echo "FAILED"
 
If "FAILED" is displayed, this is a finding.
 
Inspect the current permissions and owner of Automation Controller application content directory:

stat -c "%a %U %G" /var/lib/awx/public/static | grep -q "755 root awx" || echo "FAILED"
 
If "FAILED" is displayed, this is a finding.
 
Inspect the current permissions and owner of Automation Controller web server log directory:

stat -c "%a %U %G" /var/log/nginx| grep -q "770 nginx root" || echo "FAILED"
 
If "FAILED" is displayed, this is a finding.)
  desc 'fix', 'As a system administrator, for each Automation Controller NGINX web server host, set the permissions and owner of Automation Controller web server program configuration directory:

sudo chown -R root:root /etc/nginx/
sudo chmod 755 /etc/nginx /etc/nginx
sudo chmod 755 /etc/nginx /etc/nginx/conf.d
sudo chmod 644 /etc/nginx/nginx.conf
 
As a system administrator, for each Automation Controller NGINX web server program configuration files.

sudo chown root:root /usr/lib/systemd/system/nginx.service
sudo chmod 644 /usr/lib/systemd/system/nginx.service
 
Set the permissions and owner of Automation Controller application content directory:

sudo chmod 755 /var/lib/awx/public/static
sudo chown root:awx /var/lib/awx/public/static'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60635r903547_chk'
  tag severity: 'medium'
  tag gid: 'V-256960'
  tag rid: 'SV-256960r903547_rule'
  tag stig_id: 'APWS-AT-000700'
  tag gtitle: 'SRG-APP-000340-WSR-000029'
  tag fix_id: 'F-60577r902393_fix'
  tag satisfies: ['SRG-APP-000340-WSR-000029', 'SRG-APP-000211-WSR-000031']
  tag 'documentable'
  tag cci: ['CCI-001082', 'CCI-002235']
  tag nist: ['SC-2', 'AC-6 (10)']
end
