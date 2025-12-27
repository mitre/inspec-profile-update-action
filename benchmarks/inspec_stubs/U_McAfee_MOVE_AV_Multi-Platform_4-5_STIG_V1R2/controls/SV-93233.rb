control 'SV-93233' do
  title 'The McAfee MOVE AV On Access Scan Policy must be configured with a scan timeout of 45 seconds or more.'
  desc 'This setting configures the amount of time, in seconds, to wait for a scan to complete. The default setting is 45 seconds. This is the duration for which a McAfee MOVE AV Agent will wait for scan response of a file from the Security Virtual Machine (SVM). Typically, file scans are very fast. However, file scans may take longer due to large file size, file type, or heavy load on the SVM. If the file scan takes longer than the scan timeout limit, the file access is allowed and a scan timeout event is generated. Setting the timeout too low may result in scans of a file terminating before the scan is completed, resulting in malware potentially going undetected.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "Scan", verify "Specify maximum time for each file scan" is set to "45" seconds or more.

If "Specify maximum time for each file scan" is not set to "45" seconds or more, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select the On Access Scan policy to be configured.

Under "Scan", set "Specify maximum time for each file scan" to "45" seconds or more.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78527'
  tag rid: 'SV-93233r1_rule'
  tag stig_id: 'MV45-OAS-000002'
  tag gtitle: 'MV45-OAS-000002'
  tag fix_id: 'F-85261r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
