control 'SV-24510' do
  title 'Application owner accounts should have a dedicated application tablespace.'
  desc 'Separation of tablespaces by application helps to protect the application from resource contention and unauthorized access that could result from storage space reuses or host system access controls. Application data should be stored separately from system and custom user-defined objects to facilitate administration and management of its data storage. The SYSTEM tablespace should never be used for application data storage in order to prevent resource contention and performance degradation.'
  desc 'check', %q(From SQL*Plus (Note: The owner list below is but a sample of all possible default Oracle accounts - edit according to local circumstances):

select distinct owner, tablespace_name
from dba_SEGMENTS 
where owner not in
('SYS','SYSTEM','OUTLN','OLAPSYS','CTXSYS','WKSYS','ODM',
'ODM_MTR','MDSYS','ORDSYS','WMSYS','RMAN','XDB',
'AUDSYS','DBSNMP','GSMADMIN_INTERNAL')
order by tablespace_name;

Review the list of returned table owners with the tablespace used.

If any of the owners listed are not default Oracle accounts and use the "SYSTEM" or any other tablespace not dedicated for the application’s use, this is a Finding.

Look for multiple applications that may share a tablespace.

If no records were returned, ask the DBA if any applications use this database.

If no applications use the database, this is not a Finding.

If there are applications that do use the database or if the application uses the "SYS" or other default account and "SYSTEM" tablespace to store its objects, this is a Finding.)
  desc 'fix', 'Create and assign dedicated tablespaces for the storage of data by each application using the CREATE TABLESPACE command.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29426r4_chk'
  tag severity: 'medium'
  tag gid: 'V-3849'
  tag rid: 'SV-24510r3_rule'
  tag stig_id: 'DO0231-ORACLE11'
  tag gtitle: 'Oracle application object owner tablespaces'
  tag fix_id: 'F-26453r1_fix'
  tag responsibility: 'Database Administrator'
end
