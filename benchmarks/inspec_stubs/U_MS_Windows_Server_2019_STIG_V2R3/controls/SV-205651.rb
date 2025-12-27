control 'SV-205651' do
  title 'Windows Server 2019 users must be required to enter a password to access private keys stored on the computer.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Cryptography\\

Value Name:  ForceKeyProtection

Type:  REG_DWORD
Value:  0x00000002 (2)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System cryptography: Force strong key protection for user keys stored on the computer" to "User must enter a password each time they use a key".'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5916r354871_chk'
  tag severity: 'medium'
  tag gid: 'V-205651'
  tag rid: 'SV-205651r569188_rule'
  tag stig_id: 'WN19-SO-000350'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-5916r354872_fix'
  tag 'documentable'
  tag legacy: ['V-93493', 'SV-103579']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
