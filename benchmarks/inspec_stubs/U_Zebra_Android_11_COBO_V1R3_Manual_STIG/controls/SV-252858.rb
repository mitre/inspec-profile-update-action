control 'SV-252858' do
  title 'Zebra Android 11 must be configured to disable Bluetooth or configured via User Based Enforcement (UBE) to allow Bluetooth for only Headset Profile (HSP), HandsFree Profile (HFP), and Serial Port Profile (SPP).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled.

SFR ID: FMT_SMF_EXT.1.1 #18h'
  desc 'check', 'Determine if the AO has approved the use of Bluetooth at the site.

If the AO has not approved the use of Bluetooth, verify Bluetooth has been disabled:

On the EMM console, do the following:
1. Open "User restrictions on parent" section.
2. Verify that "Disallow Bluetooth" is toggled to "On".

On the Android 11 device, do the following:
1. Go to Settings >> Connected Devices >> Connection Preferences >> Bluetooth.
2. Ensure that it is set to "Off" and cannot be toggled to "On".

If the AO has approved the use of Bluetooth, on the Zebra Android 11 device do the following:
1. Go to Settings >> Connected Devices.
2. Verify only approved Bluetooth connected devices using approved profiles are listed.

If the AO has not approved the use of Bluetooth, and Bluetooth use is not disabled via an EMM-managed device policy, this is a finding.

If the AO has approved the use of Bluetooth, and Bluetooth devices using unauthorized Bluetooth profiles are listed on the device under "Connected devices", this is a finding.'
  desc 'fix', 'Configure the Zebra Android 11 device to disable Bluetooth or if the AO has approved the use of Bluetooth (for example, for car hands-free use), train the user to connect to only authorized Bluetooth devices using only HSP, HFP, or SPP profiles.

To disable Bluetooth use the following procedure:
On the EMM Console:
1. Open "User restrictions on parent" section.
2. Toggle "Disallow Bluetooth" to "On".

The user training requirement is satisfied in requirement ZEBR-11-008700.'
  impact 0.3
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56314r820499_chk'
  tag severity: 'low'
  tag gid: 'V-252858'
  tag rid: 'SV-252858r820501_rule'
  tag stig_id: 'ZEBR-11-001400'
  tag gtitle: 'PP-MDF-301110'
  tag fix_id: 'F-56264r820500_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
