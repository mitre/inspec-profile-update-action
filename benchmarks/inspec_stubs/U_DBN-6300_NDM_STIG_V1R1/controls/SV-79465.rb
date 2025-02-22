control 'SV-79465' do
  title 'The DBN-6300 must provide automated support for account management functions.'
  desc 'If account management functions are not automatically enforced, an attacker could gain privileged access to a vital element of the network security architecture.'
  desc 'check', 'Verify that the LDAP authentication server is configured correctly.

Navigate to Settings >> Initial Configuration >> Authentication.

Verify that the LDAP server entry is correct and that the button for "LDAP Based Authentication" is enabled.

Verify that the "Native takes precedence" button is set to "Disabled".

If the LDAP server entry is not present and enabled, and the "Native takes precedence" button is not set to "Disabled", this is a finding.'
  desc 'fix', 'Navigate to Settings >> Initial Configuration >> Authentication.

Enter the correct LDAP server entry.

Press the button for "LDAP Based Authentication" so that it is enabled.

If necessary, press the "Disabled" button for "Native takes precedence".

Press the "Commit" button.'
  impact 0.7
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-65633r3_chk'
  tag severity: 'high'
  tag gid: 'V-64975'
  tag rid: 'SV-79465r1_rule'
  tag stig_id: 'DBNW-DM-000006'
  tag gtitle: 'SRG-APP-000023-NDM-000205'
  tag fix_id: 'F-70915r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
