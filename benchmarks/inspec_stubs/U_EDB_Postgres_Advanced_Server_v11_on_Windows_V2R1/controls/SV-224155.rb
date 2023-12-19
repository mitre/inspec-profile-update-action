control 'SV-224155' do
  title 'EDB Postgres Advanced Server software modules, to include stored procedures, functions, and triggers must be monitored to discover unauthorized changes.'
  desc 'If the system were to allow any user to make changes to software modules implemented within the database, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. Monitoring is required for assurance that the protections are effective.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Review monitoring procedures and implementation evidence to verify monitoring of changes to database software libraries, related applications, and configuration files is being performed.

If the database schema (includes functions, procedures, schemas, extensions, etc.) is not being regularly checked for changes, this is a finding.'
  desc 'fix', 'Regularly run a check similar to this:

move <postgresql data directory>\\latest.schema <postgresql data directory>\\previous.schema

C:\\Program Files\\edb\\as<version>\\bin\\pg_dump -s -d edb -f <postgresql data directory>\\latest.schema

FC <postgresql data directory>\\previous.schema <postgresql data directory>\\latest.schema

If any differences are shown, ensure the differences are expected.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25828r495485_chk'
  tag severity: 'medium'
  tag gid: 'V-224155'
  tag rid: 'SV-224155r508023_rule'
  tag stig_id: 'EP11-00-003210'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-25816r495486_fix'
  tag 'documentable'
  tag legacy: ['V-100337', 'SV-109441']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
