control 'SV-77489' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x must be configured to enable On-Access scanning.'
  desc "For anti-virus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. 

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System. 

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "General" tab, next to the "On-access Scan:", verify the check box for "Enable on-access scanning (takes effect when policies are enforced)" is selected. 

Verify the "Quarantine Directory:" field is populated with "/quarantine" (or another valid location as determined by the organization).

If the check box for "Enable on-access scanning (takes effect when policies are enforced)" is not selected, this is a finding. 

If the "Quarantine Directory:" field is not populated, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. 

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "General" tab, next to the "On-access Scan:", select the check box for "Enable on-access scanning (takes effect when policies are enforced)".

In the "Quarantine Directory:" field, enter "/quarantine" (or another valid location as determined by the organization).'
  impact 0.7
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63751r1_chk'
  tag severity: 'high'
  tag gid: 'V-62999'
  tag rid: 'SV-77489r1_rule'
  tag stig_id: 'DTAVSEL-003'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68917r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
