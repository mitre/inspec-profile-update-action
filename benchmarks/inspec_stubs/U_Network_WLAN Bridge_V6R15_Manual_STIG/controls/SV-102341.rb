control 'SV-102341' do
  title 'WLAN components must be Wi-Fi Alliance certified with WPA2 or WPA3.'
  desc 'check', 'Review the WLAN equipment specification and verify it is Wi-Fi Alliance certified with either the older WPA2 certification or the newer WPA3 certification. WPA3 is preferred but not required at this time.

If the WLAN equipment is not Wi-Fi Alliance certified with WPA2 or WPA3, this is a finding.'
  desc 'fix', 'Use WLAN equipment that is Wi-Fi Alliance certified with WPA2 or WPA3.'
  impact 0.5
  ref 'DPMS Target WLAN Bridge'
  tag check_id: 'C-91405r2_chk'
  tag severity: 'medium'
  tag gid: 'V-92239'
  tag rid: 'SV-102341r1_rule'
  tag stig_id: 'WIR0114-1'
  tag gtitle: 'Wi-Fi Alliance Certified'
  tag fix_id: 'F-98447r1_fix'
  tag 'documentable'
end
