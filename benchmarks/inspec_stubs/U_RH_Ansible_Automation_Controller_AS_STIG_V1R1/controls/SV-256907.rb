control 'SV-256907' do
  title 'Automation Controller must utilize encryption when using LDAP for authentication.'
  desc 'To avoid access with malicious intent, passwords will need to be protected at all times. This includes transmission where passwords must be encrypted for security.'
  desc 'check', 'Log in to Automation Controller as an administrator and navigate to Settings >> Authentication >> LDAP settings.

If an LDAP server is configured but the "LDAP SERVER URI" field does not start with "ldaps://", this is a finding.'
  desc 'fix', 'Log in to Automation Controller as an administrator and navigate to Settings >> Authentication >> LDAP settings.

Click "Edit".

Modify the "LDAP SERVER URI" field so that it begins with "ldaps://".

Click "Save".'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60582r902289_chk'
  tag severity: 'medium'
  tag gid: 'V-256907'
  tag rid: 'SV-256907r903514_rule'
  tag stig_id: 'APAS-AT-000055'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag fix_id: 'F-60524r903514_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
