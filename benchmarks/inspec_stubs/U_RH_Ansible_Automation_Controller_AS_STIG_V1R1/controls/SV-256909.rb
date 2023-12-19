control 'SV-256909' do
  title 'Automation Controller must compare internal application server clocks at least every 24 hours with an authoritative time source.'
  desc 'When conducting forensic analysis and investigating system events, it is critical that timestamps accurately reflect the time of application events. If timestamps are not deemed to be accurate, the integrity of the forensic analysis and the associated determinations are at stake. This leaves the organization and the system vulnerable to intrusions.

'
  desc 'check', 'As a system administrator for each Automation Controller host, ensure the NTP client is configured to synchronize to an organizationally defined NTP server:

chronyc sources

If the Automation Controller host is not configured to use an organizationally defined NTP server, this is a finding.

Ensure the NTP time synchronization is operational:

chronyc activity | head -n 1 | grep "200 OK" >/dev/null || echo "FAILED"
sudo systemctl is-active chrony > /dev/null|| echo "FAILED"

If "FAILED" is displayed, this is a finding.'
  desc 'fix', 'As a system administrator, for each Automation Controller host, configure the NTP client to synchronize to an organizationally defined NTP server:

vi /etc/chrony.conf

Restart the Automation Controller host:

$ shutdown -r'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60584r902295_chk'
  tag severity: 'medium'
  tag gid: 'V-256909'
  tag rid: 'SV-256909r902297_rule'
  tag stig_id: 'APAS-AT-000093'
  tag gtitle: 'SRG-APP-000371-AS-000077'
  tag fix_id: 'F-60526r902296_fix'
  tag satisfies: ['SRG-APP-000371-AS-000077', 'SRG-APP-000372-AS-000212']
  tag 'documentable'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']
end
