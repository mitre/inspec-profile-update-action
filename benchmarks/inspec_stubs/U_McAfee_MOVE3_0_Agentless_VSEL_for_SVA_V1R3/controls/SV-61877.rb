control 'SV-61877' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 must be configured to enable On-Access scanning.'
  desc "For antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "General" tab, next to the "On-access Scan:", verify the check box for "Enable on-access scanning (takes effect when policies are enforced)" is selected.
Verify the "Quarantine Directory:" field is populated with "/quarantine" (or another valid location as determined by the organization).

If the checkbox for "Enable on-access scanning (takes effect when policies are enforced)" is not selected, this is a finding.
If the "Quarantine Directory:" field is not populated, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "General" tab, next to the "On-access Scan:", select the check box for "Enable on-access scanning (takes effect when policies are enforced)". 
In the "Quarantine Directory:" field, enter "/quarantine" (or another valid location as determined by the organization).

Click Save.'
  impact 0.7
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49431r4_chk'
  tag severity: 'high'
  tag gid: 'V-48999'
  tag rid: 'SV-61877r1_rule'
  tag stig_id: 'DTAVSEL-003'
  tag gtitle: 'DTAVSEL-003-McAfee VSEL for SVA OAS configuration'
  tag fix_id: 'F-49542r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
