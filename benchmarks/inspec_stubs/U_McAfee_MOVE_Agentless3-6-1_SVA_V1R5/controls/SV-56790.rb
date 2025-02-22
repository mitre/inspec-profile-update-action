control 'SV-56790' do
  title 'The McAfee MOVE AV Agentless SVA Scan Settings policy must be configured with the SVA cache enabled.'
  desc 'Enabling cache in the McAfee MOVE AV Agentless SVA will enable a more effective performance when scanning virtual machines.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. 

For McAfee MOVE AV Agentless 3.6.1:

From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "SVM" under the "Category" column and select the policy corresponding to it, found under the "Policy" column. 

In the Scan Settings tab MOVE AV Agentless version 3.6.1 of the Policy Settings page, next to the "SVM cache:", verify the checkbox for "Enabled" is selected.

If the checkbox for "SVM cache: Enabled" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. 

Locate "SVM" under the "Category" column and select the policy corresponding to it, found under the "Policy" column. 

In the Scan Settings tab of MOVE AV Agentless version 3.6.1 of the Policy Settings page, next to the "SVA cache:", select the checkbox for "Enabled".

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49452r8_chk'
  tag severity: 'medium'
  tag gid: 'V-43960'
  tag rid: 'SV-56790r2_rule'
  tag stig_id: 'AV-MOVE-SVA-004'
  tag gtitle: 'AV-MOVE-SVA-004-McAfee MOVE SVA Scan Cache'
  tag fix_id: 'F-49564r6_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
