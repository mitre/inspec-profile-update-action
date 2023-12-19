control 'SV-213953' do
  title 'Database software, including DBMS configuration files, must be stored in dedicated directories, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 
 
Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', %q(Determine the directory in which SQL Server has been installed:

Using SQL Server Management Studio's Object Explorer:
- Right-click [SQL Server Instance]
- Select "Facets"
- Record the value of RootDirectory

Determine the Operating System directory:
- Click "Start"
- Type "Run"
- Press "Enter"
- Type "%windir%"
- Click "Ok"
- Record the value in the address bar

Verify the SQL Server RootDirectory is not in the Operating System directory.

Compare the SQL RootDirectory and the Operating System directory. If the SQL RootDirectory is in the same directory as the Operating System, this is a finding.

Verify the SQL Server RootDirectory is not in another application's directory.

Navigate to the SQL RootDirectory using Windows Explorer.

Examine each directory for evidence another application is stored in it.

If evidence exists the SQL RootDirectory is in another application's directory, this is a finding.

If the SQL RootDirectory is not in the Operating System directory or another application's directory. This is not a finding.

Examples:
1) The Operating System directory is "C:\Windows". The SQL RootDirectory is "D:\Program Files\MSSQLSERVER\MSSQL". The MSSQLSERVER directory is not living in the Operating System directory or the directory of another application. This is not a finding.

2) The Operating System directory is "C:\Windows". The SQL RootDirectory is "C:\Windows\MSSQLSERVER\MSSQL". This is a finding.

3) The Operating System directory is "C:\Windows". The SQL RootDirectory is "D:\Program Files\Microsoft Office\MSSQLSERVER\MSSQL". The MSSQLSERVER directory is in the Microsoft Office directory, which indicates Microsoft Office is installed here. This is a finding.)
  desc 'fix', 'Re-install SQL Server application components using dedicated directories that are separate from the operating system.  
 
Relocate or reinstall other application software that currently shares directories with SQL Server components. 
 
Separate from the operating system and/or temporary storage.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15170r313642_chk'
  tag severity: 'medium'
  tag gid: 'V-213953'
  tag rid: 'SV-213953r754597_rule'
  tag stig_id: 'SQL6-D0-006800'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-15168r313643_fix'
  tag 'documentable'
  tag legacy: ['SV-93875', 'V-79169']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
