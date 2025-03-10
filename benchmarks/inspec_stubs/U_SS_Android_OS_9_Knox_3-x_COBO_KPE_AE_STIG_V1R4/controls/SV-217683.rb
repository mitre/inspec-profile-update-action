control 'SV-217683' do
  title 'Samsung Android must be configured to disallow outgoing beam.'
  desc 'Outgoing beam allows transfer of data through near field communication (NFC) and Bluetooth by touching two unlocked devices together. If it were enabled, sensitive DoD data could be transmitted.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that outgoing beam is disallowed. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Android user restrictions" group, verify that "disallow outgoing beam" is selected. 

On the Samsung Android device, open a picture, contact, or webpage and put it back to back with an unlocked outgoing beam-enabled device. Verify that outgoing beam cannot be started. 

If on the MDM console "disallow outgoing beam" is not selected, or on the Samsung Android device the user is able to successfully start outgoing beam, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disallow outgoing beam. 

On the MDM console, for the device, in the "Android user restrictions" group, select "disallow outgoing beam".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18902r362078_chk'
  tag severity: 'medium'
  tag gid: 'V-217683'
  tag rid: 'SV-217683r388482_rule'
  tag stig_id: 'KNOX-09-000800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18900r362079_fix'
  tag 'documentable'
  tag legacy: ['SV-102991', 'V-92903']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
