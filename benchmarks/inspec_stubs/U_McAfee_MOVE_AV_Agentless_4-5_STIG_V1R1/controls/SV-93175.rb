control 'SV-93175' do
  title 'The McAfee MOVE AV On Access Scan policy must be configured to scan files when reading from disk.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under On-access Scan >> Scan, verify the "When reading from disk" check box is selected.

If the "When reading from disk" check box is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "Scan", select the "When reading from disk" check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78031r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78469'
  tag rid: 'SV-93175r1_rule'
  tag stig_id: 'MV45-OAS-200005'
  tag gtitle: 'MV45-OAS-200005'
  tag fix_id: 'F-85203r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
