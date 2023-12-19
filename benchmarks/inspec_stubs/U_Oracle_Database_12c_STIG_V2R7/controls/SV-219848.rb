control 'SV-219848' do
  title 'Application owner accounts must have a dedicated application tablespace.'
  desc 'Separation of tablespaces by application helps to protect the application from resource contention and unauthorized access that could result from storage space reuses or host system access controls. Application data must be stored separately from system and custom user-defined objects to facilitate administration and management of its data storage. The SYSTEM tablespace must never be used for application data storage in order to prevent resource contention and performance degradation.'
  desc 'check', 'Run the SQL query:

select distinct owner, tablespace_name
from dba_SEGMENTS 
where owner not in
(<list of non-applicable accounts>)
order by tablespace_name;

(With respect to the list of special accounts that are excluded from this requirement, it is expected that the DBA will maintain the list to suit local circumstances, adding special accounts as necessary and removing any that are not supposed to be in use in the Oracle deployment that is under review.)

Review the list of returned table owners with the tablespace used.

If any of the owners listed are not default Oracle accounts and use the SYSTEM or any other tablespace not dedicated for the application’s use, this is a finding.

Look for multiple applications that may share a tablespace.

If no records were returned, ask the DBA if any applications use this database.

If no applications use the database, this is not a finding.

If there are applications that do use the database or if the application uses the SYS or other default account and SYSTEM tablespace to store its objects, this is a finding.'
  desc 'fix', 'Create and assign dedicated tablespaces for the storage of data by each application using the CREATE TABLESPACE command.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21559r533080_chk'
  tag severity: 'medium'
  tag gid: 'V-219848'
  tag rid: 'SV-219848r879887_rule'
  tag stig_id: 'O121-BP-023700'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21558r533081_fix'
  tag 'documentable'
  tag legacy: ['SV-75951', 'V-61461']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
