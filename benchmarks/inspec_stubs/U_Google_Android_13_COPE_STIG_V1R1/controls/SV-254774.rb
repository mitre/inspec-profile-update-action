control 'SV-254774' do
  title 'Google Android 13 must be configured to disable trust agents.'
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DOD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DOD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #22, FIA_UAU.5.1'
  desc 'check', 'Review device configuration settings to confirm that trust agents are disabled. 
 
This procedure is performed on both the EMM Administration console and the managed Google Android 13 device. 
 
On the EMM console:

COBO:

1. Open "Lock screen restrictions".
2. Verify that "Disable trust agents" is toggled to "ON".

COPE:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Disable trust agents" is toggled to "ON".
4. Select "Work Profile".
5. Verify that "Disable trust agents" is toggled to "ON".
____________________________

On the managed Google Android 13 device: 

COBO and COPE:

1. Open Settings.
2. Tap "Security". 
3. Tap "Advanced". 
4. Tap "Trust agents". 
5. Verify that all listed trust agents are disabled and cannot be enabled.
 
If on the EMM console, "disable trust agents" is not selected, or on the managed Google Android 13 device a trust agent can be enabled, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disable trust agents. 
 
On the EMM console:

COBO:

1. Open "Lock screen restrictions".
2. Toggle "Disable trust agents" to "ON".

COPE:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Toggle "Disable trust agents" to "ON".
4. Select "Work Profile".
5. Toggle "Disable trust agents" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58385r862702_chk'
  tag severity: 'medium'
  tag gid: 'V-254774'
  tag rid: 'SV-254774r862704_rule'
  tag stig_id: 'GOOG-13-007200'
  tag gtitle: 'PP-MDF-323110'
  tag fix_id: 'F-58331r862703_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
