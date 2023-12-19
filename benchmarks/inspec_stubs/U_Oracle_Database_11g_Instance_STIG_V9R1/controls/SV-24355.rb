control 'SV-24355' do
  title 'Database applications should be restricted from using static DDL statements to modify the application schema.'
  desc 'Application users by definition and job function require only the permissions to manipulate data within database objects and execute procedures within the database. The statements used to define objects in the database are referred to as Data Definition Language (DDL) statements and include the CREATE, DROP, and ALTER object statements (DDL statements do not include CREATE USER, DROP USER, or ALTER USER actions). This requirement is included here as a production system would by definition not support changes to the data definitions. Where object creation is an indirect result of DBMS operation or dynamic object structures are required by the application function as is found in some object-oriented DBMS applications, this restriction does not apply. Re-use of static data structures to recreate temporary data objects are not exempted.'
  desc 'check', "If the database being reviewed is not a production database, this check is Not a Finding.

From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

select created, owner, object_name, object_type
from dba_objects
where owner not in
 ('SYS', 'SYSTEM', 'ORDSYS', 'XDB', 'OLAPSYS', 'ODM')
and object_type <> 'SYNONYM' 
order by created, owner, object_name;

View the list of objects retuned.

If any object-creation dates do not coincide with the software maintenance and upgrade logs or are not objects documented as supporting dynamic object creation functions, then investigate the circumstances under which the object was created.

If the object is created using static definitions to store temporary data or indicates that the application uses unauthorized DDL statements, this is a Finding."
  desc 'fix', "Document known object creation that supports dynamic object assignment in the System Security Plan and authorize with the IAO.

Coordinate with the application designer to modify the application to use static objects with temporary data rather than using temporary objects.

You may use the following code to periodically monitor for recently created objects:

select created, owner, object_name, object_type
from dba_objects
where owner not in
 ('SYS', 'SYSTEM', 'ORDSYS', 'XDB', 'OLAPSYS', 'ODM')
and object_type <> 'SYNONYM' 
and created >= sysdate-30 -- Lists objects created within last 30 days
order by created, owner, object_name;"
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1113r2_chk'
  tag severity: 'low'
  tag gid: 'V-3727'
  tag rid: 'SV-24355r2_rule'
  tag stig_id: 'DG0015-ORACLE11'
  tag gtitle: 'Database applications use DDL statements to modify'
  tag fix_id: 'F-17993r1_fix'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSD-1, ECSD-2'
end
