control 'SV-103695' do
  title 'Samsung Android must be configured to disallow outgoing beam.'
  desc 'Outgoing beam allows transfer of data through near field communication (NFC) and Bluetooth by touching two unlocked devices together. If it were enabled, sensitive DoD data could be transmitted.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that Android beam is disabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "disable android beam" is selected. 

On the Samsung Android device, open a picture, contact, or webpage and put it back to back with an unlocked outgoing beam-enabled device. Verify that outgoing beam cannot be started. 

If on the MDM console "disable android beam" is not selected, or on the Samsung Android device the user is able to successfully start outgoing beam, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable Android beam. 

On the MDM console, for the device, in the "Knox restrictions" group, select "disable android beam".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(Legacy)'
  tag check_id: 'C-92925r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93609'
  tag rid: 'SV-103695r1_rule'
  tag stig_id: 'KNOX-09-000805'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-99853r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
