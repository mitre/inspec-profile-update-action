control 'SV-89265' do
  title 'DB2 and the operating system must enforce access restrictions associated with changes to the configuration of DB2 or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'The base installation directory of the database server software and instance home directory location is configurable at the time of installation.

Run the db2level command to find the installation directory of DB2 server software: 

     $db2level  

If any user other than the sysadmin and root users has write permission on these directories and subsequent subdirectories under this directory, this is a finding. 

On Linux and UNIX operating systems, the instance directory is located in the $INSTHOME/sqllib directory, where $INSTHOME is the home directory of the instance owner. 

On Windows operating systems, the instance directory is located under the /sqllib directory where the DB2 database product was installed. 

If any user other than the instance owner and the root user has write permission to instance home directory and subsequent subdirectories under it, this is a finding.'
  desc 'fix', 'Remove the write permission from non-root/non-sysadmin users on the DB2 installation base directory and instance home directory.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74477r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74591'
  tag rid: 'SV-89265r1_rule'
  tag stig_id: 'DB2X-00-008100'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-81191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
