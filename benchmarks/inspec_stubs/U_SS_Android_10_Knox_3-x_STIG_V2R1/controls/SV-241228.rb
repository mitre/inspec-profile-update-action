control 'SV-241228' do
  title 'Samsung Android must be configured to disallow outgoing beam.'
  desc 'Outgoing beam allows transfer of data through NFC and Bluetooth by touching two unlocked devices together. If it were enabled, sensitive DoD data could be transmitted.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to verify that outgoing beam is disallowed. 

This requirement is inherently met for COPE as outgoing beam in a "Profile/Workspace" cannot be initiated.

This validation procedure is applicable to COBO only.

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, in the Work Environment restrictions section, verify that "disallow outgoing beam" is selected. 

On the Samsung Android device, open a picture, contact, or web page and put it back to back with an unlocked outgoing beam-enabled device. Verify that outgoing beam cannot be started. 

If on the MDM console "outgoing beam" is not set to "disallow", or on the Samsung Android device the user is able to successfully start outgoing beam, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disallow outgoing beam. 

This requirement is inherently met for COPE as outgoing beam in a "Profile/Workspace" cannot be initiated.

This guidance is applicable to COBO only.

On the MDM console, in the Work Environment restrictions section, set "outgoing beam" to "disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44504r680323_chk'
  tag severity: 'medium'
  tag gid: 'V-241228'
  tag rid: 'SV-241228r680325_rule'
  tag stig_id: 'KNOX-10-011600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-44463r680324_fix'
  tag 'documentable'
  tag legacy: ['SV-109089', 'V-99985']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
