control 'SV-61751' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to enable the quarantine.'
  desc 'Malware incident containment has two major components: stopping the spread of malware and preventing further damage to hosts. Disinfecting a file is generally preferable to quarantining it because the malware is removed and the original file restored; however, many infected files cannot be disinfected. Accordingly, antivirus software should be configured to attempt to disinfect infected files and to either quarantine or delete files that cannot be disinfected. By enabling the Quarantine, organizations will have the ability to submit copies of unknown malware to their security software vendors for analysis and will able to conduct internal forensic evaluation.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Quarantine tab, next to Quarantine configuration, verify the checkbox for "Enabled" is selected.

If the checkbox for "Quarantine configuration: Enabled" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Quarantine tab, next to the "Quarantine configuration:", select the checkbox for "Enabled".

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49472r4_chk'
  tag severity: 'medium'
  tag gid: 'V-48873'
  tag rid: 'SV-61751r2_rule'
  tag stig_id: 'AV-MOVE-SVA-119'
  tag gtitle: 'AV-MOVE-SVA-119-McAfee MOVE quarantine'
  tag fix_id: 'F-49584r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
