control 'SV-24628' do
  title 'A single database connection configuration file should not be used to configure all database clients.'
  desc 'Many sites distribute a single client database connection configuration file to all site database users that contains network access information for all databases on the site. Such a file provides information to access databases not required by all users that may assist in unauthorized access attempts.'
  desc 'check', 'Review documented and implemented procedures contained or noted in the System Security Plan for providing database client connection information to users and user workstations. Oracle client connection information is stored in the file: 

$ORACLE_HOME/network/admin/tnsnames.ora (UNIX) %ORACLE_HOME%\\network\\admin\\tnsnames.ora (Windows)

If procedures do not indicate and implement restrictions in distribution of connection definitions to personnel/machines authorized to connect to the database, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures to distribute client connection definitions or definition files that contain only connection definitions authorized for that user or user workstation.

Include or note these procedures in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29154r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3809'
  tag rid: 'SV-24628r1_rule'
  tag stig_id: 'DG0053-ORACLE11'
  tag gtitle: 'DBMS client connection definition file'
  tag fix_id: 'F-26165r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
