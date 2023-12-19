control 'SV-82303' do
  title 'Database software directories, including SQL Server configuration files, must be stored in dedicated directories, separate from the host OS and other applications.'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit of one application can lead to an exploit of other applications sharing the same security context. For example, an exploit of a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to other applications’ database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications.'
  desc 'check', "Verify the SQL Server installations present on the server.

From a Command Prompt, type regedit.exe, and press [ENTER].

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> Microsoft SQL Server >> Instance Names. Each instance installed on the server possesses a key inside a folder under this registry entry.

Analysis Services Instances are registered in the OLAP subfolder.
Reporting Services Instances are registered in the RS subfolder.
Standard SQL Server (database engine) Instances are registered in the SQL subfolder.

Inside each one of these folders, a single key is used to reference an Instance's specific Windows Registry tree. Each key will have its own registry tree at the following registry location: HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> Microsoft SQL Server >> [INSTANCE NAME].

An [INSTANCE NAME] is listed as the Data component of a key found in one of the above OLAP, RS, or SQL folders.

To find the installation location of a particular instance, navigate to the following location in the Windows Registry:

HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> Microsoft SQL Server >> [INSTANCE NAME] >> Setup. Examine the value of the 'SqlProgramDir' key. The value of the 'SqlProgramDir' key is the SQL Server installation directory for that SQL Server Instance.

Navigate to that folder location using a Command Prompt or Windows Explorer. Only applications that are required for the functioning and administration, not use, of SQL Server should be located on the same directory node as the SQL Server software libraries.

If any files or subfolders that are not part of the SQL Server installation are in the folder, this is a finding."
  desc 'fix', 'Separate database files (software, data) into dedicated directories.'
  impact 0.3
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68381r4_chk'
  tag severity: 'low'
  tag gid: 'V-67813'
  tag rid: 'SV-82303r2_rule'
  tag stig_id: 'SQL4-00-015500'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-73929r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
