control 'SV-258657' do
  title 'The Samsung Android device must be configured to enforce that Wi-Fi Sharing is disabled.'
  desc 'Wi-Fi Sharing is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection. 
 
Wi-Fi Sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a preshared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify requirement KNOX-14-110160 ("Disallow config tethering") has been implemented.

If "Disallow config tethering" has not been implemented, this is a finding.'
  desc 'fix', 'Implement "Disallow config tethering" (refer to requirement KNOX-14-110160).'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62397r931169_chk'
  tag severity: 'medium'
  tag gid: 'V-258657'
  tag rid: 'SV-258657r931171_rule'
  tag stig_id: 'KNOX-14-125020'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62306r931170_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
