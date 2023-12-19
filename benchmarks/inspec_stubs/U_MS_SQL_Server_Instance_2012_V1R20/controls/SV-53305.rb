control 'SV-53305' do
  title 'SQL Server must support the organizational requirement to employ automated mechanisms for enforcing access restrictions.'
  desc 'When dealing with access restrictions pertaining to change control, it should be noted, any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Only qualified and authorized individuals are allowed to obtain access to information system components for the purposes of initiating changes, upgrades, and modifications.

Access restrictions for change also include application software libraries.

Examples of access restrictions include: physical and logical access controls, workflow automation, media libraries, abstract layers (i.e., changes are implemented into a third-party interface rather than directly into the information system component), and change windows (i.e., changes occur only during specified times, making unauthorized changes outside the window easy to discover).

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit of one application can lead to an exploit of other applications sharing the same security context. For example, an exploit of a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens, and is threatened by, other hosted applications. Access controls defined for one application may, by default, provide access to other applications’ database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications.'
  desc 'check', "Obtain the SQL Server software library installation directory location.

From a command prompt, type regedit.exe, and press [ENTER].

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> Microsoft SQL Server >> Instance Names. Each instance installed on the server possesses a key inside a folder under this registry entry.

Analysis Services Instances are registered in the OLAP subfolder.
Reporting Services Instances are registered in the RS subfolder.
Standard SQL Server Instances are registered in the SQL subfolder.

Inside each one of these folders, a single key is used to reference an instance's specific Windows Registry tree. Each key will have its own registry tree at the following registry location: HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> Microsoft SQL Server >> [INSTANCE NAME].

An [INSTANCE NAME] is listed as the data component of a key found in one of the above OLAP, RS, or SQL folders.  

To find the installation location of a particular instance, navigate to the following location in the Windows Registry:
 HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> Microsoft SQL Server >> [INSTANCE NAME] >> Setup.  Examine the value of the 'SqlProgramDir' key. The value of the 'SqlProgramDir' key is the SQL Server installation directory for that SQL Server Instance.

Navigate to that folder location using a command prompt or Windows Explorer. Note any custom subdirectories within the SQL Server software library directory. Only applications that are required for the functioning and administration of SQL Server should be located in the same disk directory as the SQL Server software libraries.

If any directories or files not installed with the SQL Server software exist within the SQL Server software library directory, this is a finding."
  desc 'fix', 'Install SQL Server software using directories separate from the OS and other application software library directories.

Relocate any directories or reinstall other application software that currently shares the DBMS software library directory to separate directories.

Recommend dedicating a separate partition for the SQL software libraries.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47606r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40951'
  tag rid: 'SV-53305r2_rule'
  tag stig_id: 'SQL2-00-014600'
  tag gtitle: 'SRG-APP-000129-DB-000087'
  tag fix_id: 'F-46233r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
