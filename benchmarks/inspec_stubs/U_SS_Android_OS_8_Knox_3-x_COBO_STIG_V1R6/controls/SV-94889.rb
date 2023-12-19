control 'SV-94889' do
  title 'Samsung Android 8 with Knox must be configured to: Add the MDM Client application to the Battery optimizations modes Whitelist.'
  desc 'Doze and App Standby are power-saving features that extend battery life by deferring background CPU and network activity.

If the MDM Client is put into Doze or App Standby mode, the MDM Administrator may not be able to administrate the mobile device (MD).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to add the MDM Client application to the Battery optimizations modes Whitelist.

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Battery optimizations modes Whitelist" setting in the "Android Application" rule. 
2. Verify the list contains the MDM Client.

Note: Some MDM products automatically apply this setting and there is no configuration to verify.

If the MDM console "Battery optimizations modes Whitelist" does not contain the MDM Client, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to add the MDM Client application to the Battery optimizations modes Whitelist.

On the MDM console, add the MDM Client Package name to the "Battery optimizations modes Whitelist" in the "Android Applications" rule.

Note: Some MDM products automatically apply this setting so there is no configuration setting to apply.

Note: Some MDM consoles may require (or take as an optional input) the MDM Client Signature.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79857r1_chk'
  tag severity: 'low'
  tag gid: 'V-80185'
  tag rid: 'SV-94889r1_rule'
  tag stig_id: 'KNOX-08-003200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-86991r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
