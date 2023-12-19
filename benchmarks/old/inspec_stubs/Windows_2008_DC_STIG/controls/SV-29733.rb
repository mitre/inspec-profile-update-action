control 'SV-29733' do
  title 'Users must be required to enter a password to access private keys stored on the computer.'
  desc "Configuring this setting so that users must provide a password (distinct from their domain password) every time they use a key makes it more difficult for an attacker to access locally stored user keys, even if the attacker takes control of the user's computer and determines their logon password."
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "System cryptography: Force strong key protection for user keys stored on the computer" is not set to "User must enter a password each time they use a key", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Cryptography\\

Value Name:  ForceKeyProtection

Value Type:  REG_DWORD
Value:  2'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System cryptography: Force strong key protection for user keys stored on the computer" to "User must enter a password each time they use a key".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32759r3_chk'
  tag severity: 'medium'
  tag gid: 'V-4444'
  tag rid: 'SV-29733r3_rule'
  tag gtitle: 'Strong Key Protection'
  tag fix_id: 'F-66925r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
