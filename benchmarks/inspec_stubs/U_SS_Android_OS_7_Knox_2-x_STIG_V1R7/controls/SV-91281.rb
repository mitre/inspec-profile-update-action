control 'SV-91281' do
  title 'The Samsung Android 7 with Knox must be configured to implement the management setting: Enable Container.'
  desc "The container must be enabled by the administrator/MDM or the container's protections will not apply to the mobile device. This will cause the mobile device's apps and data to be at significantly higher risk of compromise because they are not protected by encryption, isolation, etc.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device has the container enabled.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Android Knox Container" rule. 
2. Verify the existence of this rule.
3. Pushing this rule to the device that does not have a container installed will result in creation of the container.

On the Samsung Android 7 with Knox device, do the following:
1. Verify the existence of the Knox icon on the device home screen or application menu or the notification bar pull-down menu.
2. If available on the MDM agent, verify the container rule in the list of rules received by the MDM agent.

If the MDM console "Android Knox Container" cannot be configured or if the container rule is not found in the MDM agent rule list (MDM vendor-specific check), or on the Samsung Android 7 with Knox device, the Knox icon is not present, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enable the container.

On the MDM console, create the "Android Knox Container" rule and push this rule to the device.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76253r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76585'
  tag rid: 'SV-91281r1_rule'
  tag stig_id: 'KNOX-07-012800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83279r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
