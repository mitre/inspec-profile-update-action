control 'SV-95007' do
  title 'Samsung Android 8 with Knox must be configured to disable exceptions to the access control policy that prevents groups of application processes from accessing all data stored by other groups of application processes.'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DoD sensitive information. To mitigate this risk, there are data sharing restrictions. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copying/pasting data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review documentation on Samsung Android 8 with Knox and inspect the configuration on Samsung Android 8 with Knox to verify the access control policy is enabled that prevents groups of application processes from accessing all data stored by other groups of application processes.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Android Knox CONTAINER" rule. 
2. Verify the existence of this rule.
3. Pushing this rule to the device that does not have a CONTAINER installed will result in creation of the CONTAINER.

On the Samsung Android 8 with Knox device, do the following:
1. Verify the existence of the Knox icon on the device home screen or application menu or the notification bar pull-down menu.
2. If available on the MDM agent, verify the CONTAINER rule in the list of rules received by the MDM agent.

If the MDM console "Android Knox CONTAINER" rule cannot be configured, or the Knox icon is not present, or the CONTAINER rule is not found in the MDM agent rule list (MDM vendor-specific check), this is a finding. 

Note: This validation procedure is identical to the one for KNOX-08-007000 (Knox CONTAINER must be enabled). It only needs to be performed once. If it is found compliant on the first check, it is also compliant here. If it is determined to be a finding on first check, it is also a finding here. Redundant checks are necessary to maintain requirements traceability and provide complete risk management information to Authorizing Officials (AOs).'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enable the access control policy that prevents groups of application processes from accessing all data stored by other groups of application processes.

On the MDM console, create the "Android Knox CONTAINER" rule and push this rule to the device.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79975r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80303'
  tag rid: 'SV-95007r1_rule'
  tag stig_id: 'KNOX-08-006600'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-87109r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002191']
  tag nist: ['CM-6 b', 'AC-4 (2)']
end
