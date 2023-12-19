control 'SV-57769' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to enable On-Demand scanning.'
  desc 'Antivirus software is the mostly commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives and folders regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes, introduces a higher risk of threats going undetected.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the General tab of the Policy Settings page, next to the "On-Demand Scanning:", verify the checkbox for "Enabled" is selected.

If the checkbox for "On-Demand Scanning: Enabled" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the General tab of the Policy Settings page, next to the "On-Demand Scanning:", select the checkbox for "Enabled".

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49457r5_chk'
  tag severity: 'medium'
  tag gid: 'V-44935'
  tag rid: 'SV-57769r2_rule'
  tag stig_id: 'AV-MOVE-SVA-103'
  tag gtitle: 'AV-MOVE-SVA-103-McAfee Move ODS status'
  tag fix_id: 'F-49569r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
