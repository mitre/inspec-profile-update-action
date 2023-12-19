control 'SV-224157' do
  title 'Database software, including EDB Postgres Advanced Server configuration files, must be stored in dedicated directories, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'Review the DBMS software library directory and note other root directories located on the same disk directory or any subdirectories.

If any non-DBMS software directories exist on the disk directory, examine or investigate their use. If any of the directories are used by other applications, including third-party applications that use the DBMS, this is a finding.

Only applications that are required for the functioning and administration, not use, of the DBMS should be located in the same disk directory as the DBMS software libraries.

If other applications are located in the same directory as the DBMS, this is a finding.'
  desc 'fix', 'Install all applications on directories separate from the DBMS software library directory. Relocate any directories or reinstall other application software that currently shares the DBMS software library directory.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25830r495491_chk'
  tag severity: 'medium'
  tag gid: 'V-224157'
  tag rid: 'SV-224157r508023_rule'
  tag stig_id: 'EP11-00-003400'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-25818r495492_fix'
  tag 'documentable'
  tag legacy: ['SV-109445', 'V-100341']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
