control 'SV-228602' do
  title 'Google Android 11 devices must have the latest available Google Android 11 operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm the Google Android device has the most recently released version of Google Android 11 installed. 
 
This procedure is performed on both the EMM console and the Google Android 11 device.
 
In the EMM management console, review the version of Google Android 11 installed on a sample of managed devices. This procedure will vary depending on the EMM product. 
 
On the Google Android 11 device, to see the installed operating system version: 
1. Open Settings. 
2. Tap "About phone". 
3. Verify "Build number". 
 
If the installed version of the Android operating system on any reviewed Google devices is not the latest released by Google, this is a finding. 

Google's Android operating system patch website: https://source.android.com/security/bulletin/  

Android versions for Pixel devices: https://developers.google.com/android/images)
  desc 'fix', 'Install the latest released version of the Google Android 11 operating system on all managed Google devices.
 
NOTE: Google Android device operating system updates are released directly by Google or can be distributed via the EMM. Android versions for Pixel devices can be found at https://developers.google.com/android/images'
  impact 0.7
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30837r505631_chk'
  tag severity: 'high'
  tag gid: 'V-228602'
  tag rid: 'SV-228602r510289_rule'
  tag stig_id: 'GOOG-11-010800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30814r505632_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
