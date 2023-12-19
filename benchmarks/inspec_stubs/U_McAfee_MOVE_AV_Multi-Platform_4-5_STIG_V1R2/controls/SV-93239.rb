control 'SV-93239' do
  title 'The McAfee MOVE AV On Access Scan Policy must be configured to scan when reading from disk.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "Scan", verify the "When reading from disk" check box is selected.

If the "When reading from disk" check box is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Select the On Access Scan policy to be configured.

Under "Scan", select the "When reading from disk" check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78533'
  tag rid: 'SV-93239r1_rule'
  tag stig_id: 'MV45-OAS-000005'
  tag gtitle: 'MV45-OAS-000005'
  tag fix_id: 'F-85269r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
