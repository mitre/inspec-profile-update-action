control 'SV-89141' do
  title 'The OS must limit privileges to change the DB2 software resident within software libraries (including privileged programs).'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Run the db2level command to find the installation directory of DB2 server software: 

     $db2level  

If any user other than the sysadmin and root users has write permission on these directories and subsequent subdirectories under this directory, this is a finding. 

On Linux and UNIX operating systems, the instance directory is located in the $INSTHOME/sqllib directory, where $INSTHOME is the home directory of the instance owner. 

On Windows operating systems, the instance directory is located under the /sqllib directory where the DB2 database product was installed. 

If any user other than the instance owner and the root user has write permission to instance home directory and subsequent subdirectories under it, this is a finding.'
  desc 'fix', 'Remove the write permission from non-root, non-sysadmin users on the DB2 installation base directory and instance home directory.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74393r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74467'
  tag rid: 'SV-89141r1_rule'
  tag stig_id: 'DB2X-00-002900'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-81067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
