control 'SV-93231' do
  title 'The McAfee MOVE AV On Access Scan Policy must be configured to enable protection.'
  desc 'Anti-virus software should be installed as soon after operating system installation as possible and then updated with the latest signatures and anti-virus software patches (to eliminate any known vulnerabilities in the anti-virus software itself). The anti-virus software should then perform a complete scan of the host to identify any potential infections. To support the security of the host, the anti-virus software should be configured and maintained properly so it continues to be effective at detecting and stopping malware. Anti-virus software is most effective when its signatures are fully up to date. Accordingly, antivirus software should be kept current with the latest signature and software updates to improve malware detection.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "On-access scan", verify the "Enable on-access scan" check box is selected.

If the "Enable on-access scan" check box is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "On-access scan", select the "Enable on-access scan" check box.

Click "Save".'
  impact 0.7
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78093r1_chk'
  tag severity: 'high'
  tag gid: 'V-78525'
  tag rid: 'SV-93231r1_rule'
  tag stig_id: 'MV45-OAS-000001'
  tag gtitle: 'MV45-OAS-000001'
  tag fix_id: 'F-85259r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
