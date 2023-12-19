control 'SV-258422' do
  title 'Google Android 14 must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39'
  desc 'check', 'Review managed Google Android 14 device configuration settings to determine if the mobile device has a USB mass storage mode and whether it has been disabled. 

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 14 device. 

On the EMM console:

COBO:

1. Open "User restrictions".
2. Open "Set user restrictions".
3. Verify that "Disallow USB file transfer" is toggled to "ON".

COPE:

1. Open "User restrictions".
2. Open "Set user restrictions on parent".
3. Verify "Disallow USB file transfer" is toggled to "ON".
______________________________

On the managed Google Android 14 device:

1. Plug a USB cable into the managed Google Android 14 device and connect to a non-DOD network-managed PC.
2. Go to Settings >> Connected devices >> USB.
3. Verify "No data transfer" is selected.

If the EMM console device policy is not set to disable USB mass storage mode or on the managed Google Android 14 device, the device policy is not set to disable USB mass storage mode, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to disable USB mass storage mode.

On the EMM console:

COBO:

1. Open "User restrictions".
2. Open "Set user restrictions".
3. Toggle "Disallow USB file transfer" to "ON".

COPE:

1. Open "User restrictions".
2. Open "Set user restrictions on parent".
3. Toggle "Disallow USB file transfer" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 14 COPE'
  tag check_id: 'C-62163r928289_chk'
  tag severity: 'medium'
  tag gid: 'V-258422'
  tag rid: 'SV-258422r928291_rule'
  tag stig_id: 'GOOG-14-008400'
  tag gtitle: 'PP-MDF-333230'
  tag fix_id: 'F-62087r928290_fix'
  tag 'documentable'
  tag cci: ['CCI-002546']
  tag nist: ['SC-41']
end
