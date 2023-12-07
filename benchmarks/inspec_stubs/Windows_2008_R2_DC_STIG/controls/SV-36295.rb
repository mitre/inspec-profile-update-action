control 'SV-36295' do
  title 'Domain Controllers must require LDAP signing.'
  desc 'Unsigned network traffic is susceptible to man-in-the-middle attacks where an intruder captures packets between the server and the client and modifies them before forwarding them to the client.  In the case of an LDAP server, this means that an attacker can cause a client to make decisions based on false records from the LDAP directory.  You can lower the risk of an attacker pulling this off in a corporate network by implementing strong physical security measures to protect the network infrastructure.  Furthermore, implementing Internet Protocol security (IPSec) authentication header mode (AH), which performs mutual authentication and packet integrity for Internet Protocol (IP) traffic, can make all types of man-in-the-middle attacks extremely difficult.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Domain Controller: LDAP Server signing requirements" is not set to "Require signing", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE 
Registry Path:  \\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\

Value Name:  LDAPServerIntegrity

Value Type:  REG_DWORD
Value:  2

Documentable Explanation:  If LDAP Signing is not supported by a client, service or application, this must be documented with the IAO with supporting vendor information.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain controller: LDAP server signing requirements" to "Require signing".'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-51799r3_chk'
  tag severity: 'medium'
  tag gid: 'V-4407'
  tag rid: 'SV-36295r2_rule'
  tag stig_id: 'AD.3106_2008_R2'
  tag gtitle: 'LDAP Signing Requirements'
  tag fix_id: 'F-53593r1_fix'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
