control 'SV-24641' do
  title 'Database account passwords should be stored in encoded or encrypted format whether stored in database objects, external host files, environment variables or any other storage locations.'
  desc 'Database passwords stored in clear text are vulnerable to unauthorized disclosure. Database passwords should always be encoded or encrypted when stored internally or externally to the DBMS.'
  desc 'check', 'This check applies specifically to the Oracle DBMS installation and its associated files, scripts and environments.

This check does not apply to compiled, encoded or encrypted application source code and batch job code covered in Check DG0130. 

Ask the DBA to review the list of DBMS database objects, database configuration files, associated scripts and applications defined within and external to the DBMS that access the database.

The list should also include files or settings used to configure the operational environment for the DBMS and for interactive DBMS user accounts.

Ask the DBA and/or IAO to determine if any DBMS database objects, database configuration files, associated scripts and applications defined within or external to the DBMS that access the database, and DBMS / user environment files/settings contain database passwords.

If any do, confirm that DBMS passwords stored internally or externally to the DBMS are encoded or encrypted.

If any passwords are stored in clear text, this is a Finding.

If a list of DBMS database objects, database configuration files, associated scripts and applications defined within or external to the DBMS that access the database, and DBMS / user environment files/settings is not maintained in the System Security Plan, this is a Finding.'
  desc 'fix', 'Develop, document and maintain a list of DBMS database objects, database configuration files, associated scripts and applications defined within or external to the DBMS that access the database, and DBMS / user environment files/settings in the System Security Plan.

Record whether they do or do not contain DBMS passwords.

If passwords are present, ensure they are encoded or encrypted and protected by host system security.

Consider using vendor or 3rd party tools to support external authentication (i.e. Oracle Database Vault).'
  impact 0.7
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29165r1_chk'
  tag severity: 'high'
  tag gid: 'V-3812'
  tag rid: 'SV-24641r1_rule'
  tag stig_id: 'DG0067-ORACLE11'
  tag gtitle: 'DBMS account password storage'
  tag fix_id: 'F-26177r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
