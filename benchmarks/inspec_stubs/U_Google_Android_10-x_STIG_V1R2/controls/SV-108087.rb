control 'SV-108087' do
  title 'Google Android 10 devices must be configured to disable the use of third-party keyboards.'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that no third-party keyboards are enabled. 

This procedure is performed on both the MDM console and the Google Android 10 device.

In the MDM management console, review the user restrictions section.
Select "Set input methods" and insure no third-party keyboards are installed.

On the Google Android 10 device, to see if a third-party keyboard is enabled:
1. Open Settings>>System>>Languages & input. 
2. Tap "Virtual keyboard". 
3. Tap "Manage keyboard". 
4. Ensure no third-party keyboards are listed, or if third-party keyboards are present they are "Disabled by admin".

If third-party keyboards are enabled, this is a finding. 

Google's Android operating system patch website: https://source.android.com/security/bulletin/)
  desc 'fix', 'Configure Google Android 10 device to disallow the use of third-party keyboards. 

On the MDM console, in the Android user restrictions section, select "Set input methods" and ensure no third-party keyboards are installed.'
  impact 0.3
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97823r1_chk'
  tag severity: 'low'
  tag gid: 'V-98983'
  tag rid: 'SV-108087r1_rule'
  tag stig_id: 'GOOG-10-011000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-104659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
