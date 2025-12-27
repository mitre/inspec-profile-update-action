control 'SV-254744' do
  title 'Google Android 13 must be configured to disable developer modes.'
  desc 'Developer modes expose features of the mobile operating system (MOS) that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DOD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review managed Google Android 13 device configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 13 device. 

On the EMM Console:

COBO:

1. Open "Set user restrictions".
2. Verify that "Disallow debugging features" is toggled to "ON".

COPE:

1. Open "Set user restrictions".
2. Verify that "Disallow debugging features" is toggled to "ON".
3. Open "Set user restrictions on parent".
4. Verify that "Disallow debugging features" is toggled to "ON".
____________________________

On the managed Google Android 13 device:

COBO and COPE:

1. Go to Settings >> System.
2. Ensure "Developer Options" is not listed.
3. Go to Settings >> About Phone.
4. Tap on the Build Number to try to enable Developer Options and validate that action is blocked.

If the EMM console device policy is not set to disable developer mode or on the managed Google Android 13 device, the device policy is not set to disable developer mode, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disable developer modes.

On the EMM Console:

COBO:

1. Open "Set user restrictions".
2. Toggle "Disallow debugging features" to "ON".

COPE:

1. Open "Set user restrictions".
2. Toggle "Disallow debugging features" to "ON".
3. Open "Set user restrictions on parent".
4. Toggle "Disallow debugging features" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 13 COBO'
  tag check_id: 'C-58355r862429_chk'
  tag severity: 'medium'
  tag gid: 'V-254744'
  tag rid: 'SV-254744r862431_rule'
  tag stig_id: 'GOOG-13-007400'
  tag gtitle: 'PP-MDF-323130'
  tag fix_id: 'F-58301r862430_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
