control 'SV-258438' do
  title 'Android 14 devices must have the latest available Google Android 14 operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm the Google Android device has the most recently released version of managed Google Android 14 installed. 
 
This procedure is performed on both the EMM console and the managed Google Android 14 device.
 
In the EMM management console, review the version of Google Android 14 installed on a sample of managed devices. This procedure will vary depending on the EMM product. 
 
On the managed Google Android 14 device, to determine the installed operating system version: 

COBO and COPE:

1. Open Settings.
2. Tap "About phone".
3. Verify "Build number".
 
If the installed version of the Google Android 14 operating system on any reviewed devices is not the latest released by Google, this is a finding. 

Google's Android operating system patch website: https://source.android.com/security/bulletin/.

Android versions for Pixel devices: https://developers.google.com/android/images.)
  desc 'fix', 'Install the latest released version of the Google Android 14 operating system on all managed Google devices.
 
Note: Google Android device operating system updates are released directly by Google or can be distributed via the EMM. Check each device manufacturer and/or carriers for current updates.'
  impact 0.7
  ref 'DPMS Target Google Android 14 COPE'
  tag check_id: 'C-62179r928337_chk'
  tag severity: 'high'
  tag gid: 'V-258438'
  tag rid: 'SV-258438r928339_rule'
  tag stig_id: 'GOOG-14-010800'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62103r928338_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
