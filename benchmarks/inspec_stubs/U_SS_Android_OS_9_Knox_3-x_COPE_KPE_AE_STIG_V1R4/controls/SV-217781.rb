control 'SV-217781' do
  title 'Samsung Android devices must have the latest available Samsung Android operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that the most recently released version of Samsung Android is installed. 

This procedure is performed on both the MDM console and the Samsung Android device. 

In the MDM management console, review the version of Samsung Android installed on a sample of managed devices. This procedure will vary depending on the MDM product. See the notes below to determine the latest available operating system version. 

On the Samsung Android device, to see the installed operating system version: 
1. Open Settings. 
2. Tap "About phone". 
3. Tap "Software information". 

On the Samsung Android device, to confirm that the installed operating system is the latest released version: 
1. Open Settings. 
2. Tap "Software updates". 
3. Tap "Check for system updates". 
4. Verify that "No update is necessary at this time" is displayed. 

If the installed version of the Android operating system on any reviewed Samsung devices is not the latest released by the wireless carrier, this is a finding. 

Note: Some wireless carriers list the version of the latest Android operating system release by mobile device model online: 
- ATT: https://www.att.com/devicehowto/dsm.html#!/popular/make/Samsung 
- T-Mobile: https://support.t-mobile.com/docs/DOC-34510 
- Verizon Wireless: https://www.verizonwireless.com/support/software-updates/ 

Google's Android operating system patch website: https://source.android.com/security/bulletin/ 
Samsung's Android operating system patch website: https://security.samsungmobile.com/securityUpdate.smsb)
  desc 'fix', 'Install the latest released version of the Samsung Android operating system on all managed Samsung devices. 

Note: In most cases, operating system updates are released by the wireless carrier (for example, Sprint, T-Mobile, Verizon Wireless, and ATT).'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE AE'
  tag check_id: 'C-18998r362636_chk'
  tag severity: 'high'
  tag gid: 'V-217781'
  tag rid: 'SV-217781r388482_rule'
  tag stig_id: 'KNOX-09-001300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18996r362637_fix'
  tag 'documentable'
  tag legacy: ['SV-103911', 'V-93825']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
