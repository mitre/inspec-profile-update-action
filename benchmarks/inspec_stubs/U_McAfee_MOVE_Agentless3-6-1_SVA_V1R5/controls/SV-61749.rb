control 'SV-61749' do
  title 'When a threat is found by the McAfee MOVE AV Agentless On-Demand Scan, the Scan policy must be configured to notify only if first action fails.'
  desc 'Malware incident containment has two major components:  stopping the spread of malware and preventing further damage to hosts. Disinfecting a file is generally preferable to quarantining it because the malware is removed and the original file restored; however, many infected files cannot be disinfected. The primary goal of eradication is to remove malware from infected hosts.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Actions tab, next to the "On-Demand Scan: When a threat is found:", verify "Notify Only" is selected from the drop-down list for "If the first action fails, then perform this action".

If the "On-Demand Scan: When a threat is found: If the first action fails, then perform this action:" does not have "Notify Only" selected from the drop-down list, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Actions tab, next to the "On-Demand Scan: When a threat is found:", select the "Notify Only" from the "If the first action fails, then perform this action:" drop-down list.

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-50963r4_chk'
  tag severity: 'medium'
  tag gid: 'V-48871'
  tag rid: 'SV-61749r2_rule'
  tag stig_id: 'AV-MOVE-SVA-118'
  tag gtitle: 'AV-MOVE-SVA-118-McAfee MOVE scan notification'
  tag fix_id: 'F-49583r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
