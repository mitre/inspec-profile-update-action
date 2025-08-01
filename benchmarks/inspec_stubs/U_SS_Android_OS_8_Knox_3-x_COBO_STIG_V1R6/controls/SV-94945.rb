control 'SV-94945' do
  title 'Samsung Android 8 with Knox must implement the management setting: Disable Android Beam.'
  desc 'Android Beam allows transfer of data through NFC and Bluetooth by touching two unlocked devices together. If it were enabled, sensitive DoD data could be transmitted.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing disabling of Android Beam.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow Android Beam" check box in the "Android Restrictions" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device, open a picture, contact, or webpage and put it back to back with an unlocked Android Beam-enabled device. Verify Android Beam cannot be started.

If the MDM console "Allow Android Beam" is selected or on the Samsung Android 8 with Knox device, the user is able to successfully start Android Beam, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox to enforce disabling "Android Beam".

On the MDM console, deselect the "Allow Android Beam" check box in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80241'
  tag rid: 'SV-94945r1_rule'
  tag stig_id: 'KNOX-08-016000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
