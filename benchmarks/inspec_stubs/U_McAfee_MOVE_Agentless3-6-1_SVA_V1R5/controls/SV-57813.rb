control 'SV-57813' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to scan files when closed.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are written to disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "On-Access Scan files:", verify the checkbox for "On Close" is selected.

If the checkbox for "On-Access Scan files: On Close" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "On-Access Scan files:", select the checkbox for "On Close".

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49460r5_chk'
  tag severity: 'medium'
  tag gid: 'V-44979'
  tag rid: 'SV-57813r2_rule'
  tag stig_id: 'AV-MOVE-SVA-106'
  tag gtitle: 'AV-MOVE-SVA-106-McAfee MOVE scan files on close'
  tag fix_id: 'F-49572r4_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
