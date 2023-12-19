control 'SV-93269' do
  title 'The McAfee MOVE AV SVM Settings policy ODS scan interval must be set to no more than every seven days.'
  desc 'Anti-virus software is the mostly commonly used technical control for malware threat mitigation. Anti-virus software on hosts should be configured to scan all hard drives and folders regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes introduces a higher risk of threats going undetected.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "ODS Scheduler", verify the "Scan" option is selected. 

Review the schedule and verify a schedule of at least weekly is configured.

If the ODS Scheduler "Scan" option is not selected or the schedule is not configured for at least weekly, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "ODS Scheduler", select the "Scan" option. 

In the schedule, configure scan dates to accomplish at least weekly scanning.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78563'
  tag rid: 'SV-93269r1_rule'
  tag stig_id: 'MV45-SVM-000001'
  tag gtitle: 'MV45-SVM-000001'
  tag fix_id: 'F-85299r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
