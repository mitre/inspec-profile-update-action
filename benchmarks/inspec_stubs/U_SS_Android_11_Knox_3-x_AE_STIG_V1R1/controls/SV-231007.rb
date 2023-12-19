control 'SV-231007' do
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
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33937r592513_chk'
  tag severity: 'medium'
  tag gid: 'V-231007'
  tag rid: 'SV-231007r607691_rule'
  tag stig_id: 'KNOX-11-021700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33910r592514_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
