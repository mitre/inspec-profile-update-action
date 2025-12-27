control 'SV-108085' do
  title 'Google Android 10 devices must have the latest available Google Android 10 operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that the Google Android device recently released version of Google Android 10 is installed. 

This procedure is performed on both the MDM console and the Google Android 10 device.

In the MDM management console, review the version of Google Android 10 installed on a sample of managed devices. This procedure will vary depending on the MDM product. 

On the Google Android 10 device, to see the installed operating system version: 
1. Open Settings. 
2. Tap "About phone". 
3. Verify "Build number". 

If the installed version of the Android operating system on any reviewed Google devices is not the latest released by Google, this is a finding. 

Google's Android operating system patch website: https://source.android.com/security/bulletin/)
  desc 'fix', 'Install the latest released version of the Google Android 10 operating system on all managed Google devices.

Note: Google Android device operating system updates are released directly by Google or can be distributed via the MDM.'
  impact 0.7
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97821r1_chk'
  tag severity: 'high'
  tag gid: 'V-98981'
  tag rid: 'SV-108085r1_rule'
  tag stig_id: 'GOOG-10-010800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-104657r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
