control 'SV-255213' do
  title 'Microsoft Android 11 must be configured to disable developer modes.'
  desc 'Developer modes expose features of the Microsoft Android device that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DOD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Microsoft Android device configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Set user restrictions" section.
2. Verify that "Disallow debugging features" is toggled to "On".
3. Open "Set user restrictions on parent" section.
4. Verify that "Disallow debugging features" is toggled to "On".

On the Microsoft Android 11 device:
1. Go to Settings >> System.
2. Ensure Developer Options is not listed.
3. Go to Settings >> About.
4. Tap on the Build number to try to enable Developer Options and validate that action is blocked (tap on Build number several times).

If the EMM console device policy is not set to disable developer mode or on the Android 11 device, the device policy is not set to disable developer mode, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to disable developer modes.

On the EMM console:
1. Open "Set user restrictions" section.
2. Toggle "Disallow debugging features" to "On".
3. Open "Set user restrictions on parent" section.
4. Toggle "Disallow debugging features" to "On".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58826r870741_chk'
  tag severity: 'medium'
  tag gid: 'V-255213'
  tag rid: 'SV-255213r870826_rule'
  tag stig_id: 'MSFT-11-002800'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-58770r870742_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
