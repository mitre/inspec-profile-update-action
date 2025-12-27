control 'SV-61731' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to decode MIME encoded files.'
  desc 'Multipurpose Internet Mail Extensions (MIME) encoded files can be crafted to hide a malicious payload. When the MIME encoded file is presented to software that decodes the MIME encoded files, such as an email client, the malware is released. Scanning these files as part of the regularly scheduled scans tasks will mitigate this risk.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "Compressed files:", verify the checkbox for "Decode MIME encoded files" is selected.

If the checkbox for "Compressed files: Decode MIME encoded files" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "Compressed files:", select the checkbox for "Decode MIME encoded files".

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49462r5_chk'
  tag severity: 'medium'
  tag gid: 'V-48853'
  tag rid: 'SV-61731r2_rule'
  tag stig_id: 'AV-MOVE-SVA-108'
  tag gtitle: 'AV-MOVE-SVA-108-McAfee MOVE scan decode MIME encoded files'
  tag fix_id: 'F-49574r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
