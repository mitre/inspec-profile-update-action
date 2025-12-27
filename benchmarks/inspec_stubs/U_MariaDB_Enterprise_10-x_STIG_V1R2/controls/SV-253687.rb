control 'SV-253687' do
  title 'Database software, including MariaDB configuration files, must be stored in dedicated directories, separate from the host OS and other applications.'
  desc 'When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application s database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications.'
  desc 'check', 'Review the MariaDB software library directory and note other root directories located on the same disk directory or any subdirectories. The default install directory is /var/lib/mysql.

If any non-MariaDB software directories exist on the disk directory, examine or investigate their use. If any of the directories are used by other applications, including third-party applications that use MariaDB, this is a finding.

Only applications that are required for the functioning and administration, not use, of MariaDB should be located in the same disk directory as the MariaDB software libraries.

If other applications are located in the same directory as MariaDB, this is a finding.'
  desc 'fix', 'Install all applications on directories separate from the MariaDB software library directory. Relocate any directories or reinstall other application software that currently shares the MariaDB software library directory.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57139r841584_chk'
  tag severity: 'medium'
  tag gid: 'V-253687'
  tag rid: 'SV-253687r841586_rule'
  tag stig_id: 'MADB-10-002800'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-57090r841585_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
