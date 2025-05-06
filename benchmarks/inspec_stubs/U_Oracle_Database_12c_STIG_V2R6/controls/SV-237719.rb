control 'SV-237719' do
  title 'The DBMS must support enforcement of logical access restrictions associated with changes to the DBMS configuration and to the database itself.'
  desc 'When dealing with access restrictions pertaining to change control, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications.

Modifications to the DBMS settings, the database files, database configuration files, or the underlying database application files themselves could have catastrophic consequences to the database.  Modification to DBMS settings could include turning off access controls to the database, the halting of archiving, the halting of auditing, and any number of other malicious actions.'
  desc 'check', 'Review DBMS settings and vendor documentation to ensure the database supports and does not interfere with enforcement of logical access restrictions associated with changes to the DBMS configuration and to the database itself.

If the DBMS software in any way restricts the implementation of logical access controls implemented to protect its integrity or availability, this is a finding.'
  desc 'fix', 'Configure the DBMS to allow implementation of logical access restrictions aimed at protecting the DBMS from unauthorized changes to its configuration and to the database itself.

- - - - -
When the Oracle Database is installed on a Unix-like operating system, the required umask is 022, and the file permissions are set so that any modifications to the startup files can only be performed by the owner of the software, a member of the group DBA, or the root user. Changing the umask has caused problems when patching the environment.  If changes are to be made, they should be reverted to the status they were in before the modification for patching and upgrades.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40938r667187_chk'
  tag severity: 'medium'
  tag gid: 'V-237719'
  tag rid: 'SV-237719r850694_rule'
  tag stig_id: 'O121-C2-010300'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-40901r667188_fix'
  tag 'documentable'
  tag legacy: ['V-61671', 'SV-76161']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
