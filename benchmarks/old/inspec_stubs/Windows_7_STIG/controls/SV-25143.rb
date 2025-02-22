control 'SV-25143' do
  title 'The configuration of wireless devices using Windows Connect Now will be disabled.'
  desc 'This check verifies that the configuration of wireless devices using Windows Connect Now is disabled.'
  desc 'check', 'If the following registry values don’t exist or are not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars\\

Value Name:  DisableFlashConfigRegistrar
Value Name:  DisableInBand802DOT11Registrar
Value Name:  DisableUPnPRegistrar
Value Name:  DisableWPDRegistrar
Value Name:  EnableRegistrars

Type:  REG_Dword
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now “Configuration of wireless settings using Windows Connect Now” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15386r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15698'
  tag rid: 'SV-25143r1_rule'
  tag gtitle: 'Network – WCN Wireless Configuration'
  tag fix_id: 'F-15590r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
