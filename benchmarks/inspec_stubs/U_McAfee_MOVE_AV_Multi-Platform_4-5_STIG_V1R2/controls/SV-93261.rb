control 'SV-93261' do
  title 'Path Exclusions configured in the McAfee MOVE AV On Demand Scan policy must be formally documented by the System Administrator and approved by the ISSO/ISSM.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring anti-virus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware. Excluding files, paths, and processes from being scanned expands the potential for malware to be allowed onto the information system. While it is recognized that some file types might need to be excluded for operational reasons and/or because there is protection afforded to those files through a different mechanism, allowing those exclusions should always be vetted, documented, and approved before applying.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "Exclusions", verify the "Path Exclusions" include only the following paths:

**\\McAfee\\Common Framework\\
**\\Program Files\\McAfee\\Agent\\
*.log

If any Path Exclusions are included other than those specified above, and the exclusions have not been formally documented by the System Administrator and approved by the ISSO/ISSM, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "Exclusions", remove any Path Exclusions, other than the following paths, that have not been formally documented by the System Administrator and approved by the ISSO/ISSM:

**\\McAfee\\Common Framework\\
**\\Program Files\\McAfee\\Agent\\
*.log

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78125r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78555'
  tag rid: 'SV-93261r1_rule'
  tag stig_id: 'MV45-ODS-000007'
  tag gtitle: 'MV45-ODS-000007'
  tag fix_id: 'F-85291r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
