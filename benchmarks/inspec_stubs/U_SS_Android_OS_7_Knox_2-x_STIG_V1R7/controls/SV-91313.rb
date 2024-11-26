control 'SV-91313' do
  title 'The Samsung Android 7 with Knox must be configured to Add the MDM Client application to the Battery optimizations modes Whitelist.'
  desc 'Doze and App Standby are power-saving features that extend battery life by deferring background CPU and network activity.

If the MDM Client is put into Doze or App Standby mode, the MDM Administrator may not be able to administer the MDM.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to add the MDM Client application to the Battery optimizations modes Whitelist.

This validation procedure is performed on both the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Battery optimizations modes Whitelist" setting in the "Android Application" rule. 
2. Verify the list contains the MDM Client.

If the MDM console "Battery optimizations modes Whitelist" does not contain the MDM Client, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to add the MDM Client application to the Battery optimizations modes Whitelist.

On the MDM console, add the MDM Client Package name to the "Battery optimizations modes Whitelist" in the "Android Applications" rule.

Note: Some MDM consoles may require (or take as an optional input) the MDM Client Signature.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76287r1_chk'
  tag severity: 'low'
  tag gid: 'V-76617'
  tag rid: 'SV-91313r1_rule'
  tag stig_id: 'KNOX-07-018200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83311r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
