control 'SV-254480' do
  title 'Windows Server 2022 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.'
  desc 'This setting ensures the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing. FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\

Value Name: Enabled

Value Type: REG_DWORD
Value: 0x00000001 (1)
 
Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms. Both the browser and web server must be configured to use TLS; otherwise the browser will not be able to connect to a secure site.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57965r849254_chk'
  tag severity: 'medium'
  tag gid: 'V-254480'
  tag rid: 'SV-254480r849256_rule'
  tag stig_id: 'WN22-SO-000360'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag fix_id: 'F-57916r849255_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
