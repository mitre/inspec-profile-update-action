control 'SV-61881' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On-Access scanner must be configured to decompress archives when scanning.'
  desc 'Malware is often packaged within an archive. In addition, archives may have other archives within. Not scanning archive files introduces the risk of infected files being introduced into the environment.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Advanced" tab, next to the "Compressed files", verify the check box for "Scan inside multiple-file archives (e.g. .ZIP)" is selected.

If the check box for "Compressed files: Scan inside multiple-file archives (e.g. .ZIP)" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Advanced" tab, next to the "Compressed files", select the check box for "Scan inside multiple-file archives (e.g. .ZIP)".

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49432r3_chk'
  tag severity: 'medium'
  tag gid: 'V-49003'
  tag rid: 'SV-61881r1_rule'
  tag stig_id: 'DTAVSEL-004'
  tag gtitle: 'DTAVSEL-004-McAfee VSEL for SVA OAS decompress archives'
  tag fix_id: 'F-49543r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
