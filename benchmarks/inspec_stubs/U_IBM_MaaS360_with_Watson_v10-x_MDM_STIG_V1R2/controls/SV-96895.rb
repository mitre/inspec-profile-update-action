control 'SV-96895' do
  title 'The MaaS360 server must be configured to enable all required audit events (if function is not automatically implemented during MDM/MAS server install): b. Failure to update an existing application on a managed mobile device.'
  desc 'Failure to generate these audit records makes it more difficult to identify or investigate attempted or successful compromises, potentially causing incidents to last longer than necessary.

SFR ID: FMT_SMF.1.1(3) c,
FAU_GEN.1.1(2)'
  desc 'check', 'Review the MaaS360 server console and confirm the server is configured to alert for audit event failures on managed mobile devices.

On the MaaS360 Console, complete the following steps:
1. Navigate to Devices >> Groups.
2. Have the System Administrator identify one or more groups that alert for failure to update an existing application on a managed mobile device.
3. Select "edit" for one of the identified groups and verify that the two conditions exist:
- Condition 1: "Software Installed", "Application Name", "Contains", "<Name of Application>"
- Condition 2: "Software Installed", "Full Version", "Contains","<latest version of Application>"
4. Navigate to Security >> Compliance Rules.
5. Have the System Administrator identify one or more Rule Set Names that alert for failure to update an existing application on a managed mobile device.
6. Open “Rule Set Name” and select “Enforcement Rules”.
7. Verify that “Application Compliance” is enabled and "Alert" is selected for “Enforcement Action”.
8. Go to Group Based Rules and verify that the rule selected in Step 5 has been assigned to the group identified in Step 3.

If two conditions in the device group are not set correctly, or application compliance is not enabled and set correctly in the rule set name, or the rule is not assigned to the group, this is a finding.'
  desc 'fix', 'Configure the MaaS360 server to enable all required audit events: Failure to update an existing application on a managed mobile device.

On the MaaS360 Console, complete the following steps:
1. Navigate to Devices >> Groups.
2. Select "Add", "Device Groups", and create a new search with the conditions noted below.
3. Select "edit" for one of the identified groups and set the two conditions:
- Condition 1: "Software Installed", "Application Name", "Contains", "<Name of Application>"
- Condition 2: "Software Installed", "Full Version", "Contains","<latest version of Application>"
4. Select "Search" and then create a new device group and provide an appropriate group name and description.
5. Navigate to Security >> Compliance Rules.
6. Select one or more Rule Set Names that alert for failure to update an existing application on a managed mobile device. 
7. Open “Rule Set Name” and select “Enforcement Rules”.
8. Set the “Application Compliance” to “enabled” and select "Alert" for “Enforcement Action”.
9. Go to Group Based Rules and assign the rule selected in Step 6 to the group identified in Step 4.'
  impact 0.3
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81981r1_chk'
  tag severity: 'low'
  tag gid: 'V-82181'
  tag rid: 'SV-96895r1_rule'
  tag stig_id: 'M360-10-100300'
  tag gtitle: 'PP-MDM-323202'
  tag fix_id: 'F-89039r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000129', 'CCI-000169', 'CCI-000366']
  tag nist: ['AU-2 a', 'AU-12 a', 'CM-6 b']
end
