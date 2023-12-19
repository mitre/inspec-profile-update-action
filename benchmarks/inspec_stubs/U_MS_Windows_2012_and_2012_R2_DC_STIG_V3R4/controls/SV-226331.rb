control 'SV-226331' do
  title 'The system must be configured to the required LDAP client signing level.'
  desc 'This setting controls the signing requirements for LDAP clients.  This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LDAP\\

Value Name: LDAPClientIntegrity

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: LDAP client signing requirements" to "Negotiate signing" at a minimum.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28033r476837_chk'
  tag severity: 'medium'
  tag gid: 'V-226331'
  tag rid: 'SV-226331r794606_rule'
  tag stig_id: 'WN12-SO-000068'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28021r476838_fix'
  tag 'documentable'
  tag legacy: ['SV-52894', 'V-3381']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
