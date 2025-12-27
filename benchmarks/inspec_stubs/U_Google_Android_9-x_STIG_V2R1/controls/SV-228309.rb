control 'SV-228309' do
  title 'Google Android Pie devices must have the latest available Google Android Pie operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that the Google Android devicet recently released version of Google Android Pie is installed. For Google Android Pie, version PQ3A.190605.003.A3 must be installed (it is the NIAP approved version). Note: This version of Android can only be installed on Pixel 3 devices purchased directly from Google. 

This procedure is performed on both the MDM console and the Google Android Pie device. 

In the MDM management console, review the version of Google Android Pie installed on a sample of managed devices. This procedure will vary depending on the MDM product. 

On the Google Android Pie device, to see the installed operating system version: 
1. Open Settings. 
2. Tap "About phone". 
3. Verify "Build number". 

If the installed version of the Android operating system on any reviewed Samsung devices is not the latest released by the wireless carrier, this is a finding. 

Google's Android operating system patch website: https://source.android.com/security/bulletin/)
  desc 'fix', 'Install the latest released version of the Google Android Pie operating system on all managed Google devices. For Google Android Pie, version PQ3A.190605.003.A3 must be installed (it is the NIAP approved version) Note: This version of Android can only be installed on Pixel 3 devices purchased directly from Google. 

Note: In Google Android devicet cases, operating system updates are released by the wireless carrier (for example, Sprint, T-Mobile, Verizon Wireless, and ATT).'
  impact 0.7
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30542r494994_chk'
  tag severity: 'high'
  tag gid: 'V-228309'
  tag rid: 'SV-228309r494996_rule'
  tag stig_id: 'GOOG-09-010800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30527r494995_fix'
  tag 'documentable'
  tag legacy: ['SV-106471', 'V-97367']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
