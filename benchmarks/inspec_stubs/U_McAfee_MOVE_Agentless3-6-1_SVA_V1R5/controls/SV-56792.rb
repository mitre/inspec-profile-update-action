control 'SV-56792' do
  title 'The McAfee MOVE AV Agentless SVA Scan Settings policy for On-Demand Client Scan time interval must be set to no more than every 7 days.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes, introduces a higher risk of threats going undetected.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on "Actions | Agent | Modify Policies on a Single System". From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "SVA" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Settings tab of the Policy Settings page, verify the "On-Demand Scan time interval (days):" is set to "7" or less. 

If the "On-Demand Scan time interval (days):" is set to a value of more than "7", this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless]3.6.1". Locate "SVA" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Settings tab of the Policy Settings page, configure the "On-Demand Scan time interval (days):" with a value of "7" or less.

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49454r8_chk'
  tag severity: 'medium'
  tag gid: 'V-43962'
  tag rid: 'SV-56792r2_rule'
  tag stig_id: 'AV-MOVE-SVA-006'
  tag gtitle: 'AV-MOVE-SVA-006-Mcafee MOVE SVA On-Demand Scan interval'
  tag fix_id: 'F-49566r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
