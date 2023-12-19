control 'SV-224995' do
  title 'Domain controllers must require LDAP access signing.'
  desc 'Unsigned network traffic is susceptible to man-in-the-middle attacks, where an intruder captures packets between the server and the client and modifies them before forwarding them to the client. In the case of an LDAP server, this means that an attacker could cause a client to make decisions based on false records from the LDAP directory. The risk of an attacker pulling this off can be decreased by implementing strong physical security measures to protect the network infrastructure. Furthermore, implementing Internet Protocol security (IPsec) authentication header mode (AH), which performs mutual authentication and packet integrity for Internet Protocol (IP) traffic, can make all types of man-in-the-middle attacks extremely difficult.

'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\

Value Name: LDAPServerIntegrity

Value Type: REG_DWORD
Value: 0x00000002 (2)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain controller: LDAP server signing requirements" to "Require signing".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26686r465887_chk'
  tag severity: 'medium'
  tag gid: 'V-224995'
  tag rid: 'SV-224995r569186_rule'
  tag stig_id: 'WN16-DC-000320'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-26674r465888_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag legacy: ['SV-88293', 'V-73629']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
