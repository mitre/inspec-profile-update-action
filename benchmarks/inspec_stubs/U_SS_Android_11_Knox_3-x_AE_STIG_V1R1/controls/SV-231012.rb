control 'SV-231012' do
  title 'The Samsung Android device must have the latest available Samsung Android operating system (OS) installed.'
  desc 'Required security features are not available in earlier OS versions. In addition, earlier versions may have known vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android device configuration settings to confirm that the most recently released version of Samsung Android is installed.

This procedure is performed on both the management tool and the Samsung Android device. 

In the management tool management console, review the version of Samsung Android installed on a sample of managed devices. This procedure will vary depending on the management tool product. See the notes below to determine the latest available OS version.

On the Samsung Android device, to see the installed OS version:
1. Open Settings.
2. Tap "About phone".
3. Tap "Software information".

If the installed version of Android OS on any reviewed Samsung devices is not the latest released by the wireless carrier, this is a finding.

NOTE: Some wireless carriers list the version of the latest Android OS release by mobile device model online:

ATT: https://www.att.com/devicehowto/dsm.html#!/popular/make/Samsung

T-Mobile: https://support.t-mobile.com/docs/DOC-34510
Verizon Wireless: https://www.verizonwireless.com/support/software-updates/

Google Android OS patch website: https://source.android.com/security/bulletin/ 

Samsung Android OS patch website: https://security.samsungmobile.com/securityUpdate.smsb'
  desc 'fix', 'Install the latest released version of Samsung Android OS on all managed Samsung devices. 

NOTE: In most cases, OS updates are released by the wireless carrier (for example, Sprint, T-Mobile, Verizon Wireless, and ATT).'
  impact 0.7
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33942r592528_chk'
  tag severity: 'high'
  tag gid: 'V-231012'
  tag rid: 'SV-231012r607691_rule'
  tag stig_id: 'KNOX-11-023300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33915r592529_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
