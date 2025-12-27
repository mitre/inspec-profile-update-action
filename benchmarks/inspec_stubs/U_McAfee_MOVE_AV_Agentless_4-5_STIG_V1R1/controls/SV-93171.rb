control 'SV-93171' do
  title 'The McAfee MOVE AV On Access Scan policy must be configured to enforce a maximum On-Access Scan timeout of no less than 45 seconds.'
  desc 'This setting configures the amount of time, in seconds, to wait for a scan to complete. The default setting is 45 seconds. This is the duration for which a McAfee MOVE AV Agent will wait for scan response of a file from the Security Virtual Machine (SVM). Typically, file scans are very fast. However, file scans may take longer due to large file size, file type, or heavy load on the SVM. If the file scan takes longer than the scan timeout limit, the file access is allowed and a scan timeout event is generated. Setting the timeout too low may result in scans of a file terminating before the scan is completed, resulting in malware potentially going undetected.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Click "Show Advanced".

Under "On-access Scan", verify the "Specify maximum time for each file scan" is configured for "45" seconds or more.

If "Specify maximum time for each file scan" is not configured for "45" seconds or more, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Click "Show Advanced".

Under "On-access Scan", set the "Specify maximum time for each file scan" for "45" seconds or more.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78027r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78465'
  tag rid: 'SV-93171r1_rule'
  tag stig_id: 'MV45-OAS-200002'
  tag gtitle: 'MV45-OAS-200002'
  tag fix_id: 'F-85199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
