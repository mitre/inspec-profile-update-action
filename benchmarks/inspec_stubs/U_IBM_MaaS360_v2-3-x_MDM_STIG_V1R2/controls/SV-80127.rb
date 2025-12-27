control 'SV-80127' do
  title 'The MaaS360 Server must be configured to enable all required audit events: Failure to update an existing application on a managed mobile device.'
  desc 'Failure to generate these audit records makes it more difficult to identify or investigate attempted or successful compromises, potentially causing incidents to last longer than necessary.

SFR ID: FAU_GEN.1.1(2) Refinement'
  desc 'check', 'Review the MaaS360 server console and confirm the server is configured to alert for audit event failures on managed mobile devices.

On the MaaS360 Console complete the following Steps:
1. Navigate to Devices >> Groups
2. Have System Administrator identify one or more groups that alert for failure to update an existing application on a managed mobile device.
3. Select "edit" for one of the identified groups and verify that the two conditions exist:
     Condition 1: "Software Installed", "Application Name", "Contains", "<Name of Application>"
     Condition 2:  "Software Installed", "Full Version", "Contains","<latest version of Application>"
4. Navigate to Security >> Compliance Rules
5. Have System Administrator identify one or more Rule Set Names that alert for failure to update an existing application on a managed mobile device.  
6. Open Rule Set Name and select Enforcement Rules.
7. Verify that Application Compliance is enabled and "Alert" is selected for Enforcement Action
8. Then go to Group Based Rules and verify that the rule selected in Step 5 has been assigned to the group identified in Step 3.

If two conditions in device group are not set correctly or application compliance is not enabled and set correctly in the rule set name or the rule is not assigned to the group, this is a finding.'
  desc 'fix', 'Configure the MAS Server to enable all required audit events: Failure to update an existing application on a managed mobile device.

On the MaaS360 Console complete the following Steps:
1. Navigate to Devices >> Groups
2. Select one or more groups that alert for failure to update an existing application on a managed mobile device.
3. Select "edit" for one of the identified groups and set the two conditions:
     Condition 1: "Software Installed", "Application Name", "Contains", "<Name of Application>"
     Condition 2:  "Software Installed", "Full Version", "Contains","<latest version of Application>"
4. Navigate to Security >> Compliance Rules
5. Select one or more Rule Set Names that alert for failure to update an existing application on a managed mobile device.  
6. Open Rule Set Name and select Enforcement Rules.
7. Set the Application Compliance to enabled and select "Alert" for Enforcement Action
8. Then go to Group Based Rules and assign the rule selected in Step 5 to the group identified in Step 3.'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 v2.3.x MDM'
  tag check_id: 'C-66197r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65637'
  tag rid: 'SV-80127r1_rule'
  tag stig_id: 'M360-01-003850'
  tag gtitle: 'PP-MDM-203106'
  tag fix_id: 'F-71565r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000129', 'CCI-000169', 'CCI-000366', 'CCI-001571']
  tag nist: ['AU-2 a', 'AU-12 a', 'CM-6 b', 'AU-2 a']
end
