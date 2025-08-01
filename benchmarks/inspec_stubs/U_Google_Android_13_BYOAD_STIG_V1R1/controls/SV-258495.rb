control 'SV-258495' do
  title 'Android 13 devices must have the latest available Google Android 13 operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, earlier versions may have known vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm the Google Android device has the most recently released version of managed Google Android 13 installed. 
 
This procedure is performed on both the EMM console and the managed Google Android 13 device.
 
In the EMM management console, review the version of Google Android 13 installed on a sample of managed devices. This procedure will vary depending on the EMM product. 
 
To determine the installed operating system version on the managed Google Android 13 device: 

1. Open Settings.
2. Tap "About phone".
3. Verify "Build number".
 
If the installed version of the Google Android 13 operating system on any reviewed device is not the latest released by Google, this is a finding. 

Google's Android operating system patch website: https://source.android.com/security/bulletin/

Android versions for Pixel devices: https://developers.google.com/android/images)
  desc 'fix', 'Install the latest released version of the Google Android 13 operating system on all managed Google devices.
 
Note: Google Android device operating system updates are released directly by Google or can be distributed via the EMM. Check each device manufacturer and/or carriers for current updates.'
  impact 0.7
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62235r929299_chk'
  tag severity: 'high'
  tag gid: 'V-258495'
  tag rid: 'SV-258495r929301_rule'
  tag stig_id: 'GOOG-13-710800'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62144r929300_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
