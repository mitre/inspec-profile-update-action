control 'SV-61925' do
  title 'Any paths and files excluded by the McAfee VirusScan Enterprise for Linux 1.9.0 On-Access scanner must be formally documented with, and approved by, the IAO/IAM.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring antivirus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Detections" tab, next to "What not to scan:", verify the only entry for the "Select files and directories to be excluded from virus scanning" field is the default "/var/log". 

If any entries other than the default "/var/log" are present in the "What not to scan:" setting for the "Select files and directories to be excluded from virus scanning" field, verify the exclusion of those files and directories has been formally documented by the System Administrator and has been approved by the IAO/IAM.

If any entries other than the default "/var/log" are present in the "What not to scan:" setting for the "Select files and directories to be excluded from virus scanning" field, and those files and directories have not been formally documented by the System Administrator and approved by the IAO/IAM, this is a finding.

If any entries other than the default "/var/log" are present in the "What not to scan:" setting for the "Select files and directories to be excluded from virus scanning" field, and those files and directories have been formally documented by the System Administrator and approved by the IAO/IAM, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Detections" tab, next to "What not to scan:", remove all entries in the "Select files and directories to be excluded from virus scanning" field other than the default "/var/log". 
Document justification for any required exclusions and obtain approval from the IAO/IAM.

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49440r3_chk'
  tag severity: 'medium'
  tag gid: 'V-49039'
  tag rid: 'SV-61925r1_rule'
  tag stig_id: 'DTAVSEL-012'
  tag gtitle: 'DTAVSEL-012-McAfee VSEL for SVA OAS file exclusions'
  tag fix_id: 'F-49551r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
