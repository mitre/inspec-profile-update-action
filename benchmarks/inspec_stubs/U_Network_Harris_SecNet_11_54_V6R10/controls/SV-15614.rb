control 'SV-15614' do
  title 'WLAN SSIDs must be changed from the manufacturer’s default to a pseudo random word that does not identify the unit, base, organization, etc.'
  desc 'An SSID identifying the unit, site or purpose of the WLAN or is set to the manufacturer default may cause an OPSEC vulnerability.'
  desc 'check', "Review device configuration. 
1. Obtain the SSID using a wireless scanner or the AP or WLAN controller management software.  
2. Verify the name is not meaningful (e.g., site name, product name, room number, etc.) or set to the manufacturer's default value.

Mark as a finding if the SSID does not meet the requirement listed above."
  desc 'fix', 'Change the SSID to a pseudo random word that does not identify the unit, base, or organization.'
  impact 0.3
  ref 'DPMS Target Harris Secnet 11'
  tag check_id: 'C-13276r1_chk'
  tag severity: 'low'
  tag gid: 'V-14846'
  tag rid: 'SV-15614r1_rule'
  tag stig_id: 'WIR0105'
  tag gtitle: 'Change WLAN SSID default'
  tag fix_id: 'F-34142r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
