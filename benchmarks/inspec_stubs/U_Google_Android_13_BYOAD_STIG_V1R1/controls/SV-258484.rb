control 'SV-258484' do
  title 'Google Android 13 must be configured to disable trust agents.'
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DOD sensitive data if compromised. By not permitting the use of nonpassword authentication mechanisms, users are forced to use passcodes that meet DOD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #22, FIA_UAU.5.1'
  desc 'check', 'Review device configuration settings to confirm that trust agents are disabled at the same location where the DOD password is implemented (device or work profile).

This procedure is performed on both the EMM Administration console and the managed Google Android 13 device.
 
On the EMM console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Disable trust agents" is toggled to "ON".
4. Open "Lock screen restrictions".
5. Select "Work Profile".
6. Verify that "Disable trust agents" is toggled to "ON".

On the managed Google Android 13 device: 

1. Open Settings.
2. Tap "Security & privacy". 
3. Tap "More security settings". 
4. Tap "Trust agents". 
5. Verify that all listed trust agents are disabled and cannot be enabled.
 
If on the EMM console, "disable trust agents" is not selected, or on the managed Google Android 13 device a trust agent can be enabled, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disable trust agents at the same location where the DOD password is implemented (device or work profile).
 
On the EMM console:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Toggle "Disable trust agents" to "ON".
4. Open "Lock screen restrictions".
5. Select "Work Profile".
6. Toggle "Disable trust agents" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62224r929266_chk'
  tag severity: 'medium'
  tag gid: 'V-258484'
  tag rid: 'SV-258484r929268_rule'
  tag stig_id: 'GOOG-13-707200'
  tag gtitle: 'PP-MDF-333110'
  tag fix_id: 'F-62133r929267_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
