control 'SV-237331' do
  title 'The ArcGIS Server must use a full disk encryption solution to protect the confidentiality and integrity of all information.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive) within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

This requirement addresses protection of user-generated data, as well as, operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', %q(Review the ArcGIS Server configuration to ensure mechanisms that protect the confidentiality and integrity of all information at rest are provided. Substitute the target environment’s values for [bracketed] variables. 

1. Log on to https://[server.domain.com]:6443/arcgis/admin/data/items/fileShares ("Primary Site Administrator" account access is required.)

Open each "Child Items" entry >> click "Edit".

Note the "path" value. For example, "path": "\\[server.domain.com\share".

Verify the infrastructure system(s) that supply each path implement FIPS 140-2 compliant encryption at rest, such as through the use of BitLocker full disk encryption.

If any infrastructure system(s) that supply each path do not implement FIPS 140-2 compliant encryption at rest, such as through the use of BitLocker full disk encryption, this is a finding.

2. Log on to https://[server.domain.com]:6443/arcgis/admin/data/items/enterpriseDatabases ("Primary Site Administrator" account access is required.)

Open each "Child Items" entry >> click "Edit".

Note the "info" values "SERVER", "DBCLIENT", and "DATABASE", for example: 'SERVER=dbserver', 'DBCLIENT=sqlserver', 'DATABASE=vtest';

Verify on each "SERVER", "DBCLIENT", and "DATABASE", that these systems implement FIPS 140-2 compliant encryption at rest, such as through the use of SQL Server TDE (Transparent Data Encryption).

If any "SERVER", "DBCLIENT", and "DATABASE" do not implement FIPS 140-2 compliant encryption at rest, such as through the use of SQL Server TDE (Transparent Data Encryption), this is a finding.)
  desc 'fix', %q(Configure the ArcGIS Server to ensure mechanisms that protect the confidentiality and integrity of all information at rest are provided. Substitute the target environment’s values for [bracketed] variables. 

Log on to https://[server.domain.com]:6443/arcgis/admin/data/items/fileShares ("Primary Site Administrator" account access is required.)

Open each "Child Items" entry >> click "Edit".

Note the "path" value. For example, "path": "\\[server.domain.com\share".

Implement FIPS 140-2 compliant encryption at rest (such as BitLocker full disk encryption) on each infrastructure system that supplies each file path.

Log on to https://[server.domain.com]:6443/arcgis/admin/data/items/enterpriseDatabases ("Primary Site Administrator" account access is required.)

Open each "Child Items" entry >> click "Edit".

Note the "info" values "SERVER", "DBCLIENT", and "DATABASE", for example: 
'SERVER=dbserver', 'DBCLIENT=sqlserver', 'DATABASE=vtest';

Implement FIPS 140-2 compliant encryption at rest such as through the use of SQL Server TDE (Transparent Data Encryption) on each "SERVER", "DBCLIENT", and "DATABASE" entry identified above.)
  impact 0.7
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40550r642810_chk'
  tag severity: 'high'
  tag gid: 'V-237331'
  tag rid: 'SV-237331r879642_rule'
  tag stig_id: 'AGIS-00-000102'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-40513r642811_fix'
  tag 'documentable'
  tag legacy: ['SV-79973', 'V-65483']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
