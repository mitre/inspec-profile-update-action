control 'SV-256903' do
  title "Automation Controller's log files must be accessible by explicitly defined privilege."
  desc 'A failure of the confidentiality of Automation Controller log files would enable an attacker to identify key information about the system that they might not otherwise be able to obtain that would enable them to enumerate more information to enable escalation or lateral movement.

'
  desc 'check', %q(As an administrator, log into each Automation Controller host. Inspect the current permissions and owner of Automation Controller's NGINX log directory:
stat -c "%a %U %G" /var/log/nginx/ | grep "770 nginx root" || echo "FAILED"

If "FAILED" is displayed, this is a finding.

Inspect the current permissions and owner of Automation Controller's log directory:
$ stat -c "%a %U %G" /var/log/tower/ | grep "750 awx awx" || echo "FAILED"

If "FAILED" is displayed, this is a finding.

Inspect the current permissions and owner of Automation Controller's supervisor log directory:
stat -c "%a %U %G" /var/log/supervisor/ | grep "770 root root" || echo "FAILED"

If "FAILED" is displayed, this is a finding.)
  desc 'fix', "As a system administrator for each Automation Controller host, set the permissions and owner of Automation Controller's NGINX log directory:
chmod 770 /var/log/nginx
chown nginx:root /var/log/nginx

Set the permissions and owner of Automation Controller's log directory: 
chmod 770 /var/log/tower
chown awx:awx /var/log/tower

Set the permissions and owner of Automation Controller's supervisor log directory:
chmod 770 /var/log/supervisor/
chown root:root /var/log/supervisor/"
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60578r903539_chk'
  tag severity: 'medium'
  tag gid: 'V-256903'
  tag rid: 'SV-256903r903539_rule'
  tag stig_id: 'APAS-AT-000034'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag fix_id: 'F-60520r902278_fix'
  tag satisfies: ['SRG-APP-000118-AS-000078', 'SRG-APP-000119-AS-000079', 'SRG-APP-000120-AS-000080', 'SRG-APP-000121-AS-000081', 'SRG-APP-000122-AS-000082', 'SRG-APP-000123-AS-000083', 'SRG-APP-000267-AS-000170']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'SI-11 b', 'AU-9 a', 'AU-9', 'AU-9']
end
