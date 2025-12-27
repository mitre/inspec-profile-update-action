control 'SV-230085' do
  title 'The Motorola Android Pie must be configured to disable Bluetooth or configured via User Based Enforcement (UBE) to allow Bluetooth for only HSP (Headset Profile), HFP (HandsFree Profile), or SPP (Serial Port Profile) capable devices.'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore must be disabled.

SFR ID: FMT_SMF_EXT.1.1 #18h'
  desc 'check', 'Determine if the AO has approved the use of Bluetooth at the site.

If the AO has not approved the use of Bluetooth, verify Bluetooth has been disabled.

On the MDM console: 
1. Open Restrictions section.
2. Verify "Disallow Bluetooth" is set.

On the Android Pie device: 
1. Go to Settings >> Connected Devices >> Connection Preferences >> Bluetooth.
2. Verify this is set to "Off" and cannot be toggled to "On".

If the AO has approved the use of Bluetooth, on the Android Pie device: 
1. Go to Settings >> Connected Devices.
2. Verify only approved Bluetooth-connected devices using approved profiles are listed.

If the AO has not approved the use of Bluetooth, and Bluetooth use is not disabled via an MDM managed device policy, this is a finding.

If the AO has approved the use of Bluetooth, and Bluetooth devices using unauthorized Bluetooth profiles are listed on the device under "Connected devices", this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to disable Bluetooth or, if the AO has approved the use of Bluetooth (for example, for car hands-free use), train the user to connect to only authorized Bluetooth devices using only HSP, HFP, or SPP Bluetooth capable devices (User Based Enforcement (UBE).

To disable Bluetooth, use the following procedure.

On the MDM console: 
1. Open Restrictions section.
2. Toggle "Disallow Bluetooth" to "On".

The user training requirement is satisfied in requirement MOTO-09-008700.'
  impact 0.3
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32400r538251_chk'
  tag severity: 'low'
  tag gid: 'V-230085'
  tag rid: 'SV-230085r569708_rule'
  tag stig_id: 'MOTO-09-001400'
  tag gtitle: 'GOOG-09-001400'
  tag fix_id: 'F-32378r538252_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
