control 'SV-254783' do
  title 'Google Android 13 must be configured to disable Bluetooth or configured via User Based Enforcement (UBE) to allow Bluetooth for only Headset Profile (HSP), Hands-Free Profile (HFP), and Serial Port Profile (SPP).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DOD data without encryption or otherwise do not meet DOD IT security policies and therefore must be disabled.

SFR ID: FMT_SMF_EXT.1.1/BLUETOOTH BT-8'
  desc 'check', 'Determine if the AO has approved the use of Bluetooth at the site.

If the AO has not approved the use of Bluetooth, verify Bluetooth has been disabled.

On the EMM console:

COBO:

1. Open "User restrictions" section.
2. Verify "Disallow Bluetooth" is toggled to "ON".

COPE:

1. Open "User restrictions on parent" section.
2. Verify "Disallow Bluetooth" is toggled to "ON".

On the managed Google Android 13 device:

COBO and COPE:

1. Go to Settings >> Connected Devices >> Connection Preferences >> Bluetooth.
2. Verify "Use Bluetooth" is set to OFF and cannot be toggled to "ON".

If the AO has approved the use of Bluetooth, on the managed Android 13 device:

1. Go to Settings >> Connected Devices.
2. Verify only approved Bluetooth connected devices using approved profiles are listed.

If the AO has not approved the use of Bluetooth, and Bluetooth use is not disabled via an EMM-managed device policy, this is a finding.

If the AO has approved the use of Bluetooth, and Bluetooth devices using unauthorized Bluetooth profiles are listed on the device under "Connected devices", this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disable Bluetooth or if the AO has approved the use of Bluetooth (for example, for car hands-free use), train the user to connect to only authorized Bluetooth devices using only HSP, HFP, or SPP Bluetooth capable devices (UBE).

To disable Bluetooth use the following procedure:

On the EMM Console:

COBO:

1. Open "User restrictions" section.
2. Toggle "Disallow Bluetooth" to "ON".

COPE:

1. Open "User restrictions on parent" section.
2. Toggle "Disallow Bluetooth" to "ON".

The user training requirement is satisfied in requirement GOOG-13-009800.'
  impact 0.3
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58394r862729_chk'
  tag severity: 'low'
  tag gid: 'V-254783'
  tag rid: 'SV-254783r862731_rule'
  tag stig_id: 'GOOG-13-009400'
  tag gtitle: 'PP-MDF-323320'
  tag fix_id: 'F-58340r862730_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
