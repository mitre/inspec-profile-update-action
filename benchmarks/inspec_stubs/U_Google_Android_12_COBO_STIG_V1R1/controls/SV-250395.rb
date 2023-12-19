control 'SV-250395' do
  title "Google Android 12 must be configured to disable trust agents. 
 
Note: This requirement is not applicable (NA) for specific biometric authentication factors included in the product's Common Criteria evaluation."
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #22, FIA_UAU.5.1'
  desc 'check', 'Review device configuration settings to confirm that trust agents are disabled. 
 
This procedure is performed on both the EMM Administration console and the managed Google Android 12 device. 
 
On the EMM console:

COBO:

1. Open "Lock screen restrictions".
2. Verify that "Disable trust agents" is toggled to ON.

COPE:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Disable trust agents" is toggled to ON.
4. Select "Work Profile".
5. Verify that "Disable trust agents" is toggled to ON.
____________________________

On the managed Google Android 12 device: 

COBO and COPE:

1. Open Settings.
2. Tap "Security". 
3. Tap "Advanced". 
4. Tap "Trust agents". 
5. Verify that all listed trust agents are disabled and cannot be enabled.
 
If on the EMM console, "disable trust agents" is not selected, or on the managed Google Android 12 device a trust agent can be enabled, this is a finding.'
  desc 'fix', 'Configure the Google Android 12 device to disable trust agents. 
 
On the EMM console:

COBO:

1. Open "Lock screen restrictions".
2. Toggle "Disable trust agents" to ON.

COPE:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Toggle "Disable trust agents" to ON.
4. Select "Work Profile".
5. Toggle "Disable trust agents" to ON.'
  impact 0.5
  ref 'DPMS Target Google Android 12 COBO'
  tag check_id: 'C-53830r802734_chk'
  tag severity: 'medium'
  tag gid: 'V-250395'
  tag rid: 'SV-250395r802736_rule'
  tag stig_id: 'GOOG-12-007200'
  tag gtitle: 'PP-MDF-323110'
  tag fix_id: 'F-53784r802735_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
