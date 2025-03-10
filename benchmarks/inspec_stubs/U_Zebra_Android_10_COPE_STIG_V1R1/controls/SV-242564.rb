control 'SV-242564' do
  title 'Zebra Android 10 devices must be configured to disable the use of third-party keyboards.'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that no third-party keyboards are enabled. 
 
This procedure is performed on both the MDM Administration Console and the Zebra Android 10 device.
 
On the MDM console, review the user restrictions section.

Select "Set input methods" and ensure no third-party keyboards are installed.
 
On the Zebra Android 10 device:
1. Open Settings >> System >> Languages & input. 
2. Tap "Virtual keyboard". 
3. Tap "Manage keyboard". 
4. Verify that no third-party keyboards are listed or that if present, they are "Disabled by admin".
 
If third-party keyboards are enabled, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to disallow the use of third-party keyboards. 
 
On the MDM console, in the Android user restrictions section, select "Set input methods" and ensure no third-party keyboards are installed.'
  impact 0.3
  ref 'DPMS Target Zebra Android 10 COPE'
  tag check_id: 'C-45839r714535_chk'
  tag severity: 'low'
  tag gid: 'V-242564'
  tag rid: 'SV-242564r714537_rule'
  tag stig_id: 'ZEBR-10-011000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-45796r714536_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
