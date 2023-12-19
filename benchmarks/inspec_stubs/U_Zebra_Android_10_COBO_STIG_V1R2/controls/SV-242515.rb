control 'SV-242515' do
  title 'Zebra Android 10 must be configured to disable trust agents.'
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. If compromised, this technology would allow unauthorized users to have access to DoD sensitive data. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review device configuration settings to confirm that trust agents are disabled. 
 
This procedure is performed on both the MDM Administration Console and the Zebra Android 10 device. 
 
On the MDM console:
1. Open Restrictions section.
2. Set "Disable trust agents" to On.

On the Zebra Android 10 device: 
1. Open Settings. 
2. Tap "Security". 
3. Tap "Advanced". 
4. Tap "Trust agents". 
5. Verify that all listed trust agents are disabled and cannot be enabled. 
 
If on the MDM console "disable trust agents" is not selected or on the Zebra Android 10 device a trust agent can be enabled, this is a finding.'
  desc 'fix', 'Configure Zebra Android 10 to disable trust agents. 
 
On the MDM console:
1. Open Lock screen restrictions section.
2. Set "Disable trust agents" to On.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45790r714388_chk'
  tag severity: 'medium'
  tag gid: 'V-242515'
  tag rid: 'SV-242515r714390_rule'
  tag stig_id: 'ZEBR-10-002300'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-45747r714389_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
