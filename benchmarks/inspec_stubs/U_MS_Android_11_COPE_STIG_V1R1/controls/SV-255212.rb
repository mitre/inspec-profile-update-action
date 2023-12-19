control 'SV-255212' do
  title "Microsoft Android 11 must be configured to disable trust agents.  Note: This requirement is not applicable (NA) for specific biometric authentication factors included in the product's Common Criteria evaluation."
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DOD sensitive data if compromised. By not permitting the use of nonpassword authentication mechanisms, users are forced to use passcodes that meet DOD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review device configuration settings to confirm that trust agents are disabled. 
 
This procedure is performed on both the EMM Administration console and the Microsoft Android 11 device. 
 
On the EMM console:
1. Open "Lock screen restrictions" section.
2. Select "Personal Profile".
3. Verify that "Disable trust agents" is toggled to "On".
4. Select "Work Profile".
5. Verify that "Disable trust agents" is toggled to "On".

On the Microsoft Android 11 device: 
1. Open Settings. 
2. Tap "Security". 
3. Tap "Advanced". 
4. Tap "Trust agents". 
5. Verify that all listed trust agents are disabled and cannot be enabled. 
 
If on the EMM console "disable trust agents" is not selected, or on the Android 11 device a trust agent can be enabled, this is a finding.'
  desc 'fix', 'Configure Microsoft Android 11 device to disable trust agents. 
 
On the EMM console:
1. Open "Lock screen restrictions" section.
2. Select "Personal Profile".
3. Toggle "Disable trust agents" to "On".
4. Select "Work Profile".
5. Toggle "Disable trust agents" to "On".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58825r869251_chk'
  tag severity: 'medium'
  tag gid: 'V-255212'
  tag rid: 'SV-255212r870825_rule'
  tag stig_id: 'MSFT-11-002300'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-58769r869252_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
