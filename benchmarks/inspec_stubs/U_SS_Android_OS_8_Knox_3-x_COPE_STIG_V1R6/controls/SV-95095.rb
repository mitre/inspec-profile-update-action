control 'SV-95095' do
  title 'The Samsung Android 8 with Knox device must have the latest available Samsung Android operating system (OS) installed.'
  desc 'Required security features are not available in earlier OS versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review configuration settings to confirm the most recently released version of Samsung Android is installed.

This validation procedure is performed on both the MDM console and the Samsung Android 8 with Knox device. 

In the MDM management console, review the version of Samsung Android installed on a sample of managed devices. This procedure will vary depending on the MDM product. See the notes below to determine the latest available OS version.

On the Samsung device:
1. Open the "Settings".
2. Tap "About phone" and then "Software information" to see the version number of the installed Android OS.
3. Tap "Software update" and "Check for updates" to determine if an OS update is available.
4. Verify the following message is shown on the screen: "Current software is up to date".

If the installed version of Android OS on any reviewed Samsung devices is not the latest released by the wireless carrier, this is a finding.

Note: Some wireless carriers list the version of the latest Android OS release by mobile device model online:
ATT: https://www.att.com/devicehowto/dsm.html#!/popular/make/Samsung
T-Mobile: https://support.t-mobile.com/docs/DOC-34510
Verizon Wireless: https://www.verizonwireless.com/support/software-updates/

Google's Android OS patch website: https://source.android.com/security/bulletin/ 
Samsung's Android OS patch web site: https://security.samsungmobile.com/securityUpdate.smsb)
  desc 'fix', 'Install the latest released version of Samsung Android OS on all managed Samsung devices. 

Note: In most cases, OS updates are released by the wireless carrier (for example, Sprint, T-Mobile, Verizon Wireless, and ATT).'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80063r1_chk'
  tag severity: 'high'
  tag gid: 'V-80391'
  tag rid: 'SV-95095r1_rule'
  tag stig_id: 'KNOX-08-018450'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87197r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
