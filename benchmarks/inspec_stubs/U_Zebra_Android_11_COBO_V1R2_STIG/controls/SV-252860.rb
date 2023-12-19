control 'SV-252860' do
  title 'Zebra Android 11 must be configured to disable trust agents.'
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review device configuration settings to confirm that trust agents are disabled. 
 
This procedure is performed on both the EMM Administration console and the Zebra Android 11 device. 
 
On the EMM console:
1. Open "Lock screen restrictions" section.
2. Select "Personal Profile".
3. Verify that "Disable trust agents" is toggled to "On".
4. Select "Work Profile".
5. Verify that "Disable trust agents" is toggled to "On".

On the Zebra Android 11 device: 
1. Open "Settings". 
2. Tap "Security". 
3. Tap "Advanced". 
4. Tap "Trust agents". 
5. Verify that all listed trust agents are disabled and cannot be enabled. 
 
If on the EMM console "disable trust agents" is not selected, or on the Android 11 device a trust agent can be enabled, this is a finding.'
  desc 'fix', 'Configure Zebra Android 11 device to disable trust agents. 
 
On the EMM console:
1. Open "Lock screen restrictions" section.
2. Select "Personal Profile".
3. Toggle "Disable trust agents" to "On".
4. Select "Work Profile".
5. Toggle "Disable trust agents" to "On".'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56316r820505_chk'
  tag severity: 'medium'
  tag gid: 'V-252860'
  tag rid: 'SV-252860r820507_rule'
  tag stig_id: 'ZEBR-11-002300'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-56266r820506_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
