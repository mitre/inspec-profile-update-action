control 'SV-213878' do
  title 'The confidentiality and integrity of information managed by SQL Server must be maintained during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When receiving data, SQL Server, associated applications, and infrastructure must leverage protection mechanisms.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

If SQL Server, associated applications, and infrastructure do not employ protective measures against unauthorized disclosure and modification during reception, this is a finding.'
  desc 'fix', 'Implement protective measures against unauthorized disclosure and modification during reception.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15097r312985_chk'
  tag severity: 'medium'
  tag gid: 'V-213878'
  tag rid: 'SV-213878r855550_rule'
  tag stig_id: 'SQL4-00-035100'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-15095r312986_fix'
  tag 'documentable'
  tag legacy: ['SV-82401', 'V-67911']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
