control 'SV-29273' do
  title 'The system is not configured to recommended LDAP client signing requirements.'
  desc 'This setting controls the signing requirements for LDAP clients.  This setting should be set to Negotiate signing or Require signing depending on the environment and type of LDAP server in use.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.
	
If the value for “Network security: LDAP client signing requirements” is not set to at least “Negotiate signing”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LDAP\\

Value Name:  LDAPClientIntegrity

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: LDAP client signing requirements” to “Negotiate signing” at a minimum.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-14464r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3381'
  tag rid: 'SV-29273r1_rule'
  tag gtitle: 'LDAP Client Signing'
  tag fix_id: 'F-143r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
