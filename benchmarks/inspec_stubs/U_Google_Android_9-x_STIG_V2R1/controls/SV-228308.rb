control 'SV-228308' do
  title 'Google Android Pie must configured to disallow outgoing beam.'
  desc 'Outgoing beam allows transfer of data through near field communication (NFC) and Bluetooth by touching two unlocked devices together. If it were enabled, sensitive DoD data could be transmitted. 

Because of the security risks of sharing sensitive DoD data, users must not be able to allow outgoing beam.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the Google Android Pie device configuration settings to confirm that outgoing beam is disallowed. 

This procedure is performed on both the MDM Administration console and the Google Android Pie device. 

On the MDM console, in the Android user restrictions section, select "Disallow outgoing beam" to on".

On the Google Android Pie device, do the following: 
1. Open Settings. 
2. Tap "Connected devices". 
3. Tap "Connection preferences". 
4. Verify that "Android Beam" is off and grayed out.

If on the MDM console "Disallow outgoing beam" is not set to on, or on the Google Android Pie device "Android Beam" is not off and grayed out, this is a finding.'
  desc 'fix', 'Configure Google Android Pie device to disallow outgoing beam. 

On the MDM console, in the Android user restrictions section, select "Disallow outgoing beam" to on.'
  impact 0.5
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30541r494991_chk'
  tag severity: 'medium'
  tag gid: 'V-228308'
  tag rid: 'SV-228308r494993_rule'
  tag stig_id: 'GOOG-09-010400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30526r494992_fix'
  tag 'documentable'
  tag legacy: ['SV-106469', 'V-97365']
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
