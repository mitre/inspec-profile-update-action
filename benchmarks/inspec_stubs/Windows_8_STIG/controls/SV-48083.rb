control 'SV-48083' do
  title 'The system must be configured to the required LDAP client signing level.'
  desc 'This setting controls the signing requirements for LDAP clients.  This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.
	
If the value for "Network security: LDAP client signing requirements" is not set to at least "Negotiate signing", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LDAP\\

Value Name: LDAPClientIntegrity

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: LDAP client signing requirements" to "Negotiate signing" at a minimum.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44822r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3381'
  tag rid: 'SV-48083r1_rule'
  tag stig_id: 'WN08-SO-000068'
  tag gtitle: 'LDAP Client Signing'
  tag fix_id: 'F-41221r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
