control 'SV-226350' do
  title 'Domain controllers must require LDAP access signing.'
  desc 'Unsigned network traffic is susceptible to man in the middle attacks where an intruder captures packets between the server and the client and modifies them before forwarding them to the client.  In the case of an LDAP server, this means that an attacker could cause a client to make decisions based on false records from the LDAP directory.  You can lower the risk of an attacker pulling this off in a corporate network by implementing strong physical security measures to protect the network infrastructure.  Furthermore, implementing Internet Protocol security (IPSec) authentication header mode (AH), which performs mutual authentication and packet integrity for Internet Protocol (IP) traffic, can make all types of man in the middle attacks extremely difficult.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\

Value Name: LDAPServerIntegrity

Value Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain controller: LDAP server signing requirements" to "Require signing".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28052r476894_chk'
  tag severity: 'medium'
  tag gid: 'V-226350'
  tag rid: 'SV-226350r794677_rule'
  tag stig_id: 'WN12-SO-000090-DC'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-28040r476895_fix'
  tag 'documentable'
  tag legacy: ['SV-51140', 'V-4407']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
