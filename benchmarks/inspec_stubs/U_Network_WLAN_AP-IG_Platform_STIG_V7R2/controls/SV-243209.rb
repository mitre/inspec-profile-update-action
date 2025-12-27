control 'SV-243209' do
  title 'WLAN components must be Wi-Fi Alliance certified with WPA2 or WPA3.'
  desc 'Wi-Fi Alliance certification ensures compliance with DoD interoperability requirements between various WLAN products.'
  desc 'check', 'Review the WLAN equipment specification and verify it is Wi-Fi Alliance certified with either the older WPA2 certification or the newer WPA3 certification. WPA3 is preferred but not required at this time.

If the WLAN equipment is not Wi-Fi Alliance certified with WPA2 or WPA3, this is a finding.'
  desc 'fix', 'Use WLAN equipment that is Wi-Fi Alliance certified with WPA2 or WPA3.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-IG Platform'
  tag check_id: 'C-46484r720080_chk'
  tag severity: 'medium'
  tag gid: 'V-243209'
  tag rid: 'SV-243209r720082_rule'
  tag stig_id: 'WLAN-NW-000400'
  tag gtitle: 'SRG-NET-000063'
  tag fix_id: 'F-46441r720081_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
