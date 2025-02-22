control 'SV-214031' do
  title 'SQL Server Mirroring endpoint must utilize AES encryption.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

SQL Mirroring endpoints support different encryption algorithms, including no-encryption. Using a weak encryption algorithm or plaintext in communication protocols can lead to data loss, data manipulation and/or connection hijacking.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, and the requirement is documented and authorized, this is not a finding.

If Database Mirroring is in use, run the following to check for encrypted transmissions:  

SELECT name, type_desc, encryption_algorithm_desc
FROM sys.database_mirroring_endpoints
WHERE encryption_algorithm != 2

If any records are returned, this is a finding.'
  desc 'fix', 'Run the following to enable encryption on the mirroring endpoint:

ALTER ENDPOINT <Endpoint Name>
FOR DATABASE_MIRRORING
(ENCRYPTION = REQUIRED ALGORITHM AES)'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15248r313876_chk'
  tag severity: 'medium'
  tag gid: 'V-214031'
  tag rid: 'SV-214031r879887_rule'
  tag stig_id: 'SQL6-D0-016500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-15246r313877_fix'
  tag 'documentable'
  tag legacy: ['SV-94029', 'V-79323']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
