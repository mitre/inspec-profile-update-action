control 'SV-253401' do
  title 'Windows 11 must be configured to require a minimum pin length of six characters or greater.'
  desc 'Windows allows the use of PINs as well as biometrics for authentication without sending a password to a network or website where it could be compromised. Longer minimum PIN lengths increase the available combinations an attacker would have to attempt. Shorter minimum length significantly reduces the strength.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\PINComplexity\\

Value Name: MinimumPINLength

Type: REG_DWORD
Value: 6 (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> PIN Complexity >> "Minimum PIN length" to "6" or greater.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56854r829285_chk'
  tag severity: 'medium'
  tag gid: 'V-253401'
  tag rid: 'SV-253401r829287_rule'
  tag stig_id: 'WN11-CC-000260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56804r829286_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
