control 'SV-235060' do
  title 'Honeywell Mobility Edge Android Pie devices must configured to disallow outgoing beam.'
  desc 'Outgoing beam allows transfer of data through near field communication (NFC) and Bluetooth by touching two unlocked devices together. If it were enabled, sensitive DoD data could be transmitted. 
 
Because of the security risks of sharing sensitive DoD data, users must not be able to allow outgoing beam.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the Honeywell Android Pie  device configuration settings to confirm that outgoing beam is disallowed. 
 
This procedure is performed on both the MDM Administration console and the Honeywell Android Pie device. 
 
On the MDM console, in the Android user restrictions section, verify that "Disallow outgoing beam" is set to "On".
 
On the Honeywell Android Pie device: 
1. Open Settings. 
2. Tap "Connected devices". 
3. Tap "Connection preferences". 
4. Verify that "Android Beam" is off and grayed out.
 
If on the MDM console "Disallow outgoing beam" is not set to "On", or on the Honeywell Android Pie device "Android Beam" is not off and grayed out, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android Pie device to disallow outgoing beam. 
 
On the MDM console, in the Android user restrictions section, set "Disallow outgoing beam" to "On".'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38248r626546_chk'
  tag severity: 'medium'
  tag gid: 'V-235060'
  tag rid: 'SV-235060r626547_rule'
  tag stig_id: 'HONW-09-010400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-38211r623091_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
