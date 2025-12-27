control 'SV-206546' do
  title 'Database software, including DBMS configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'Review the DBMS software library directory and note other root directories located on the same disk directory or any subdirectories.

If any non-DBMS software directories exist on the disk directory, examine or investigate their use. If any of the directories are used by other applications, including third-party applications that use the DBMS, this is a finding.

Only applications that are required for the functioning and administration, not use, of the DBMS should be located in the same disk directory as the DBMS software libraries.

If other applications are located in the same directory as the DBMS, this is a finding.

For databases located on mainframes, confirm that the database and its configuration files are isolated in their own DASD pools.

If database software and database configuration files share DASD with other applications, this is a finding.'
  desc 'fix', 'Install all applications on directories separate from the DBMS software library directory. Relocate any directories or reinstall other application software that currently shares the DBMS software library directory.

For mainframe-based databases, locate database software and configuration files in separate DASD pools from other mainframe applications.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6806r291306_chk'
  tag severity: 'medium'
  tag gid: 'V-206546'
  tag rid: 'SV-206546r617447_rule'
  tag stig_id: 'SRG-APP-000133-DB-000199'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-6806r291307_fix'
  tag 'documentable'
  tag legacy: ['SV-42750', 'V-32413']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
