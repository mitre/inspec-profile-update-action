control 'SV-93183' do
  title 'The McAfee MOVE AV policy must be configured to enable On-Demand scanning.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Anti-virus software on hosts should be configured to scan all hard drives and folders regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes introduces a higher risk of threats going undetected.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "On-demand Scan", verify the "Enable on-demand scan" check box is selected.

If the "Enable on-demand scan" check box is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "On-demand Scan", select the "Enable on-demand scan" check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78477'
  tag rid: 'SV-93183r1_rule'
  tag stig_id: 'MV45-ODS-200001'
  tag gtitle: 'MV45-ODS-200001'
  tag fix_id: 'F-85211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
