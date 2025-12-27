control 'SV-228616' do
  title 'Google Android 11 must be configured to disable developer modes.'
  desc 'Developer modes expose features of the Google Android device that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Google Android device configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM Console:
1. Open "Set user restrictions" section.
2. Verify that "Disallow debugging features" is toggled to On.
3. Open "Set user restrictions on parent" section.
4. Verify that "Disallow debugging features" is toggled to On.

On the Android 11 device, do the following:

1. Go to Settings >> System.
2. Ensure Developer Options is not listed.
3. Go to Settings >> About Phone.
4. Tap on the Build Number to try to enable Developer Options and validate that action is blocked.

If the EMM console device policy is not set to disable developer mode or on the Android 11 device, the device policy is not set to disable developer mode, this is a finding.'
  desc 'fix', 'Configure the Google Android 11 device to disable developer modes.

On the EMM Console:
1. Open "Set user restrictions" section.
2. Toggle "Disallow debugging features" to On.
3. Open "Set user restrictions on parent" section.
4. Toggle "Disallow debugging features" to On.'
  impact 0.5
  ref 'DPMS Target Google Android 11 COPE'
  tag check_id: 'C-30851r505845_chk'
  tag severity: 'medium'
  tag gid: 'V-228616'
  tag rid: 'SV-228616r505847_rule'
  tag stig_id: 'GOOG-11-002800'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-30828r505846_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
