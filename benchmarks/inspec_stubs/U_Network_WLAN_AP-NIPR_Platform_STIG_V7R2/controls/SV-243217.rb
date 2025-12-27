control 'SV-243217' do
  title "WLAN SSIDs must be changed from the manufacturer's default to a pseudo random word that does not identify the unit, base, organization, etc."
  desc 'An SSID identifying the unit, site, or purpose of the WLAN or that is set to the manufacturer default may cause an OPSEC vulnerability.'
  desc 'check', "Review device configuration. 

1. Obtain the SSID using a wireless scanner or the AP or WLAN controller management software.
2. Verify the name is not meaningful (e.g., site name, product name, room number, etc.) and is not set to the manufacturer's default value.

If the SSID does not meet the requirement listed above, this is a finding."
  desc 'fix', 'Change the SSID to a pseudo random word that does not identify the unit, base, or organization.'
  impact 0.3
  ref 'DPMS Target Network WLAN AP-NIPR Platform'
  tag check_id: 'C-46492r720104_chk'
  tag severity: 'low'
  tag gid: 'V-243217'
  tag rid: 'SV-243217r720106_rule'
  tag stig_id: 'WLAN-NW-000200'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-46449r720105_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
