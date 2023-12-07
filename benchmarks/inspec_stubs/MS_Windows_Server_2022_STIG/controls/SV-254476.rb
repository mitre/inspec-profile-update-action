control 'SV-254476' do
  title 'Windows Server 2022 must be configured to at least negotiate signing for LDAP client signing.'
  desc 'This setting controls the signing requirements for LDAP clients. This must be set to "Negotiate signing" or "Require signing", depending on the environment and type of LDAP server in use.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LDAP\\

Value Name: LDAPClientIntegrity

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network security: LDAP client signing requirements to "Negotiate signing" at a minimum.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57961r849242_chk'
  tag severity: 'medium'
  tag gid: 'V-254476'
  tag rid: 'SV-254476r849244_rule'
  tag stig_id: 'WN22-SO-000320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57912r849243_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
