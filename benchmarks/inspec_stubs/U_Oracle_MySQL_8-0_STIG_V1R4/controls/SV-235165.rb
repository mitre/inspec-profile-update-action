control 'SV-235165' do
  title 'Database software, including MySQL Database Server 8.0 configuration files, must be stored in dedicated directories, or DASD pools (remove), separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', "Review the MySQL Database Server 8.0  software library directory and note other root directories located on the same disk directory or any subdirectories.

To list directory variables run:
show variables where variable_name like '%dir%';

If any non-MySQL Database Server 8.0 software directories exist on the datadir, basedir, or other non tmpdir directories, examine or investigate their use. 

If any of the directories are used by other applications, including third-party applications that use the MySQL Database Server 8.0, this is a finding.

Only applications that are required for the functioning and administration, not use, of the MySQL Database Server 8.0 should be located in the same disk directory as the DBMS software libraries. 

If other applications are located in the same directory as the DBMS, this is a finding.

To determine where the mysql configuration file(s) are being stored and which configuration file(s) was used for which variables, run the following command:
SELECT t1.*, VARIABLE_VALUE 
       FROM performance_schema.variables_info t1 
       JOIN performance_schema.global_variables t2 
         ON t2.VARIABLE_NAME=t1.VARIABLE_NAME where length(t1.variable_path) > 0;

If result of VARIABLE_PATH shows that configuration values are not stored in files dedicated directories separate from the host os or other applications, this is a finding."
  desc 'fix', 'Install all applications on directories separate from the DBMS software library directory. Relocate any directories or reinstall other application software that currently shares the DBMS software library directory.

If it is determined that configuration (options files) are inappropriately located, take the steps to move and protect these files and reconfigure mysqld startup commands to point to new the file location by setting the "--defaults-file" to point to the new location and filename for the mysql configuration file.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38384r623615_chk'
  tag severity: 'medium'
  tag gid: 'V-235165'
  tag rid: 'SV-235165r879586_rule'
  tag stig_id: 'MYS8-00-008500'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-38347r623616_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
