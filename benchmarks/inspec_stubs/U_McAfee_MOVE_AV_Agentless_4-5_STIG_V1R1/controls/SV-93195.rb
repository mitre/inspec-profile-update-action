control 'SV-93195' do
  title 'The McAfee MOVE AV On-Demand Scan interval must be set to no more than every seven days.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Anti-virus software on hosts should be configured to scan all hard drives and folders regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes introduces a higher risk of threats going undetected.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "On-demand Scan", verify the "Run on-demand scan for every _ days" is configured to "7" days or less.

If the "Run on-demand scan for every _ days" is not configured to "7" days or less, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "On-demand Scan", configure the "Run on-demand scan for every _ days" to "7" days or less.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78051r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78489'
  tag rid: 'SV-93195r1_rule'
  tag stig_id: 'MV45-ODS-200008'
  tag gtitle: 'MV45-ODS-200008'
  tag fix_id: 'F-85223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
