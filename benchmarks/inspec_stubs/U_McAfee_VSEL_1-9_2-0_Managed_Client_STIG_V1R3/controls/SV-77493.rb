control 'SV-77493' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to find unknown program viruses.'
  desc 'Due to the ability of malware to mutate after infection, standard anti-virus signatures may not be able to catch new strains or variants of the malware. Typically, these strains and variants will share unique characteristics with others in their virus family. By using a generic signature to detect the shared characteristics, using wildcards where differences lie, the generic signature can detect viruses even if they are padded with extra, meaningless code. This method of detection is Heuristic detection.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System. 

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Advanced" tab, next to "Heuristics:", verify the check box for "Find unknown program viruses" is selected.

If the check box for "Heuristics: Find unknown program viruses" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. 

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Advanced" tab, next to "Heuristics:", select the check box for "Find unknown program viruses".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63003'
  tag rid: 'SV-77493r1_rule'
  tag stig_id: 'DTAVSEL-005'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68921r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
