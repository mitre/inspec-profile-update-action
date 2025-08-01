control 'SV-213877' do
  title 'The confidentiality and integrity of information managed by SQL Server must be maintained during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, SQL Server, associated applications, and infrastructure must leverage transmission protection mechanisms.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

If SQL Server, associated applications, and infrastructure do not employ protective measures against unauthorized disclosure and modification during preparation for transmission, this is a finding.'
  desc 'fix', 'Implement protective measures against unauthorized disclosure and modification during preparation for transmission.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15096r312982_chk'
  tag severity: 'medium'
  tag gid: 'V-213877'
  tag rid: 'SV-213877r855549_rule'
  tag stig_id: 'SQL4-00-035000'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-15094r312983_fix'
  tag 'documentable'
  tag legacy: ['SV-82399', 'V-67909']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
