control 'SV-220830' do
  title 'Enhanced anti-spoofing for facial recognition must be enabled on Window 10.'
  desc 'Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support it.'
  desc 'check', 'Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures\\

Value Name: EnhancedAntiSpoofing

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Biometrics >> Facial Features >> "Configure enhanced anti-spoofing" to "Enabled". 

v1607:
The policy name is "Use enhanced anti-spoofing when available".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22545r554975_chk'
  tag severity: 'medium'
  tag gid: 'V-220830'
  tag rid: 'SV-220830r569187_rule'
  tag stig_id: 'WN10-CC-000195'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22534r554976_fix'
  tag 'documentable'
  tag legacy: ['SV-78167', 'V-63677']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
