control 'SV-61747' do
  title 'When a threat is found by the McAfee MOVE AV Agentless On-Demand Scan, the Scan policy must be configured to delete files automatically as first action.'
  desc 'Malware incident containment has two major components: stopping the spread of malware and preventing further damage to hosts. Disinfecting a file is generally preferable to quarantining it because the malware is removed and the original file restored; however, many infected files cannot be disinfected. The primary goal of eradication is to remove malware from infected hosts.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Actions tab, next to the "On-Demand Scan: When a threat is found:", verify "Delete files automatically" is selected from the drop-down list for "Perform this action first".

If the "On-Demand Scan: When a threat is found: Perform this action first:" does not have "Delete files automatically" selected from the drop-down list, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System.  From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Actions tab, next to the "On-Demand Scan: When a threat is found:", select "Delete files automatically" from the "Perform this action first:" drop-down list.

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49470r4_chk'
  tag severity: 'medium'
  tag gid: 'V-48869'
  tag rid: 'SV-61747r2_rule'
  tag stig_id: 'AV-MOVE-SVA-117'
  tag gtitle: 'AV-MOVE-SVA-117-McAfee MOVE ODS scan first action'
  tag fix_id: 'F-49582r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
