control 'SV-253366' do
  title 'Wi-Fi Sense must be disabled.'
  desc "Wi-Fi Sense automatically connects the system to known hotspots and networks that contacts have shared. It also allows the sharing of the system's known networks to contacts. Automatically connecting to hotspots and shared networks can expose a system to unsecured or potentially malicious systems."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config\\

Value Name: AutoConnectAllowedOEM

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> WLAN Service >> WLAN Settings>> "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56819r829180_chk'
  tag severity: 'medium'
  tag gid: 'V-253366'
  tag rid: 'SV-253366r829182_rule'
  tag stig_id: 'WN11-CC-000065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56769r829181_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
