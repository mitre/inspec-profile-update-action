control 'SV-95009' do
  title 'Samsung Android 8 with Knox must be configured to implement the management setting: Enable CONTAINER.'
  desc "The CONTAINER must be enabled by the Administrator/MDM or the CONTAINER's protections will not apply to the mobile device. This will cause the mobile device's apps and data to be at significantly higher risk of compromise because they are not protected by encryption, isolation, etc.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has the CONTAINER enabled.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Android Knox CONTAINER" rule. 
2. Verify the existence of this rule.
3. Pushing this rule to the device that does not have a CONTAINER installed will result in creation of the CONTAINER.

On the Samsung Android 8 with Knox device, do the following:
1. Verify the existence of the Knox icon on the device home screen or application menu or the notification bar pull-down menu.
2. If available on the MDM agent, verify the CONTAINER rule in the list of rules received by the MDM agent.

If the MDM console "Android Knox CONTAINER" cannot be configured, or if the CONTAINER rule is not found in the MDM agent rule list (MDM vendor-specific check), or on the Samsung Android 8 with Knox device, the Knox icon is not present, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enable the CONTAINER.

On the MDM console, create the "Android Knox CONTAINER" rule and push this rule to the device.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80305'
  tag rid: 'SV-95009r1_rule'
  tag stig_id: 'KNOX-08-007000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
