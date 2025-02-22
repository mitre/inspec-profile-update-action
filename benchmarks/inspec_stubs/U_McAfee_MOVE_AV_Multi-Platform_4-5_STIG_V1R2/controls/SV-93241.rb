control 'SV-93241' do
  title 'The McAfee MOVE AV On Access Scan Policy must be configured to scan all file types.'
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
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78535'
  tag rid: 'SV-93241r1_rule'
  tag stig_id: 'MV45-OAS-000006'
  tag gtitle: 'MV45-OAS-000006'
  tag fix_id: 'F-85271r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
