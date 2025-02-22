control 'SV-61741' do
  title 'For any path or file exclusions configured in the McAfee MOVE AV Agentless Scan policy, those exclusions must be formally documented by the System Administrator and approved by the IAO/IAM.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware. The excluding of files, paths, and processes from being scanned expands the potential for malware to be allowed onto the information system. While it is recognized that some file types might need to be excluded for operational reasons and/or because there is protection afforded to those files through a different mechanism, allowing those exclusions should always be vetted, documented and approved before applying.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. 

From the "Product:" drop-down list, select “MOVE AV [Agentless] 3.6.1”. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the “Exclusions” tab, verify the "Path and File Exclusion:" does not have any entry other than the default "**\\McAfee\\Common Framework\\". 

If any entries other than the default "**\\McAfee\\Common Framework\\" do exist, verify those exclusions have been formally documented by the System Administrator and approved by the ISSO/ISSM.

If there are entries in the "Path and File Exclusion:" other than the default "**\\McAfee\\Common Framework\\" and those exclusions have not been formally documented by the System Administrator and approved by the ISSO/ISSM, this is a finding. 

If the "Path and File Exclusion:" has been populated with any exclusions other than the default, and those exclusions have been formally documented by the System Administrator and approved by the ISSO/ISSM, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

From the "Product:" drop-down list, select “MOVE AV [Agentless] 3.6.1”. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the “Exclusions” tab, removed any entries from the "Path and File Exclusion:" which have not been documented by the System Administrator and approved by the IAO/IAM.

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49467r6_chk'
  tag severity: 'medium'
  tag gid: 'V-48863'
  tag rid: 'SV-61741r2_rule'
  tag stig_id: 'AV-MOVE-SVA-113'
  tag gtitle: 'AV-MOVE-SVA-113-McAfee MOVE scan file exclusions'
  tag fix_id: 'F-49579r5_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
