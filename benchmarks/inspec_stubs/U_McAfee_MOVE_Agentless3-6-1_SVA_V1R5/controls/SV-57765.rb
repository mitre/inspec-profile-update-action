control 'SV-57765' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to enable On-Access scanning.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Antivirus software should be configured to perform real-time scans of each file as it is downloaded, opened, or executed.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the General tab of the Policy Settings page, next to the "On-Access Scanning:", verify the checkbox for "Enabled" is selected.

If the checkbox for "On-Access Scanning: Enabled" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the General tab of the Policy Settings page, next to the "On-Access Scanning:", select the checkbox for "Enabled".

Click on Save.'
  impact 0.7
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49455r4_chk'
  tag severity: 'high'
  tag gid: 'V-44931'
  tag rid: 'SV-57765r2_rule'
  tag stig_id: 'AV-MOVE-SVA-101'
  tag gtitle: 'AV-MOVE-SVA-101-McAfee MOVE SVA On-Access scanning status'
  tag fix_id: 'F-49567r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
