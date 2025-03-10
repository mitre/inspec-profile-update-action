control 'SV-93177' do
  title 'The McAfee MOVE AV On Access Scan policy must be configured to scan all file types.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring anti-virus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "File Types to Scan", verify the "All files" radio button is selected.

If the File Types to Scan "All files" radio button is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "File Types to Scan", select the "All files" radio button.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78033r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78471'
  tag rid: 'SV-93177r1_rule'
  tag stig_id: 'MV45-OAS-200006'
  tag gtitle: 'MV45-OAS-200006'
  tag fix_id: 'F-85205r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
