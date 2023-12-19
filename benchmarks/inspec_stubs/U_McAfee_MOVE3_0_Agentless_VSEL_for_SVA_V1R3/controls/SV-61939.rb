control 'SV-61939' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On-Access scanner must be configured to deny access to the file if scanning fails.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, verify the "If scanning fails:" "Deny access to the file" radio button is selected.

If the "If scanning fails: Deny access to the file" radio button is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, select the "If scanning fails:" "Deny access to the file" radio button is selected.

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-50131r2_chk'
  tag severity: 'medium'
  tag gid: 'V-49051'
  tag rid: 'SV-61939r1_rule'
  tag stig_id: 'DTAVSEL-017'
  tag gtitle: 'DTAVSEL-017-McAfee VSEL for SVA OAS scan failure action'
  tag fix_id: 'F-52387r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
