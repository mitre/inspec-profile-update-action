control 'SV-253389' do
  title 'Enhanced anti-spoofing for facial recognition must be enabled on Windows 11.'
  desc 'Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support it.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures\\

Value Name: EnhancedAntiSpoofing

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Biometrics >> Facial Features >> "Configure enhanced anti-spoofing" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56842r829249_chk'
  tag severity: 'medium'
  tag gid: 'V-253389'
  tag rid: 'SV-253389r829251_rule'
  tag stig_id: 'WN11-CC-000195'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56792r829250_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
