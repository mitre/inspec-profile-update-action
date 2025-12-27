control 'SV-61927' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On-Access scanner must be configured to Clean infected files automatically as first action when a virus or Trojan is detected.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, next to "When Viruses and Trojans are found:", verify the radio button for "Clean infected files automatically" is selected.

If, next to "When Viruses and Trojans are found:", the radio button for "Clean infected files automatically" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, next to "When Viruses and Trojans are found:", select the radio button for "Clean infected files automatically".

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49441r3_chk'
  tag severity: 'medium'
  tag gid: 'V-49041'
  tag rid: 'SV-61927r1_rule'
  tag stig_id: 'DTAVSEL-013'
  tag gtitle: 'DTAVSEL-013-McAfee VSEL for SVA OAS first action'
  tag fix_id: 'F-49552r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
