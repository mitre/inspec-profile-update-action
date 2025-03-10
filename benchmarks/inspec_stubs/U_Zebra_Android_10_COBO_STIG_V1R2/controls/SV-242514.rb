control 'SV-242514' do
  title 'Zebra Android 10 must be configured to disable Bluetooth or configured via User Based Enforcement (UBE) to allow Bluetooth for only Headset Profile (HSP), HandsFree Profile (HFP), and Serial Port Profile (SPP).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled.

SFR ID: FMT_SMF_EXT.1.1 #18h'
  desc 'check', 'Determine if the AO has approved the use of Bluetooth at the site.

If the AO has not approved the use of Bluetooth, verify Bluetooth has been disabled by doing the following:

On the MDM console:
1. Open Restrictions section.
2. Verify "Disallow Bluetooth" is set.

On the Zebra Android 10 device:
1. Go to Settings >> Connected Devices >> Connection Preferences >> Bluetooth.
2. Verify that it is set to Off and cannot be toggled to On.

If the AO has approved the use of Bluetooth, on the Zebra Android 10 device do the following:

1. Go to Settings >> Connected Devices.
2. Verify only approved Bluetooth connected devices using approved profiles are listed.

If the AO has not approved the use of Bluetooth, and Bluetooth use is not disabled via an MDM managed device policy, this is a finding.

If the AO has approved the use of Bluetooth, and Bluetooth devices using unauthorized Bluetooth profiles are listed on the device under "Connected devices", this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to disable Bluetooth or, if the AO has approved the use of Bluetooth (for example, for automobile hands-free use), train the user to connect to only authorized Bluetooth devices using only HSP, HFP, or SPP Bluetooth-capable devices (UBE).

To disable Bluetooth, use the following procedure.

On the MDM console:
1. Open Restrictions section.
2. Toggle "Disallow Bluetooth" to On.

The user training requirement is satisfied in requirement ZEBR-10-008700.'
  impact 0.3
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45789r714385_chk'
  tag severity: 'low'
  tag gid: 'V-242514'
  tag rid: 'SV-242514r852810_rule'
  tag stig_id: 'ZEBR-10-001400'
  tag gtitle: 'PP-MDF-301110'
  tag fix_id: 'F-45746r714386_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
