control 'SV-93179' do
  title 'Path or file exclusions configured in the McAfee MOVE AV On Access Scan policy must be formally documented by the System Administrator and approved by the ISSO/ISSM.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring anti-virus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware. Excluding files, paths, and processes from being scanned expands the potential for malware to be allowed onto the information system. While it is recognized that some file types might need to be excluded for operational reasons and/or because protection is afforded to those files through a different mechanism, allowing those exclusions should always be vetted, documented, and approved before applying.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "Exclusions", verify no Path Exclusions have been configured other than the following:

**\\McAfee\\Common Framework\\
**\\Program Files\\McAfee\\Agent\\
*.log

If any Path Exclusions are configured and those Path Exclusions have not been formally documented by the System Administrator and approved by the ISSO/ISSM, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "Exclusions", remove any Path Exclusions that have been configured other than the following and that have not been formally documented by the System Administrator and approved by the ISSO/ISSM:

**\\McAfee\\Common Framework\\
**\\Program Files\\McAfee\\Agent\\
*.log

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78035r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78473'
  tag rid: 'SV-93179r1_rule'
  tag stig_id: 'MV45-OAS-200007'
  tag gtitle: 'MV45-OAS-200007'
  tag fix_id: 'F-85207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
