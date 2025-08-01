control 'SV-95985' do
  title 'The WebSphere Application Server files must be owned by the non-root WebSphere user ID.'
  desc 'Having files owned by the root or administrator user is an indication that the WebSphere processes are being run with escalated privileges. Running as root/admin user gives attackers elevated privileges that can be used to compromise the system more easily compared to operating the WebSphere processes with regular user privileges.

Specifying a regular OS user when installing and managing WebSphere is best practice. By doing so, the WebSphere files will be owned by the user ID specified rather than being owned by the admin user.

Use the underlying OS file permissions to ensure that access to the WebSphere files are restricted to only those users who require access.'
  desc 'check', 'Review System Security Plan documentation.

Interview the system administrator.

Determine the OS user and group information associated with the WebSphere processes.

Identify the paths, files, and folders associated with the WebSphere installation.

These include:
- <WAS_HOME>: where you installed WebSphere. 

<WAS_HOME> default location:

For UNIX: /opt/IBM/WebSphere/AppServer
For Windows: C:\\Program Files\\IBM\\WebSphere\\AppServer

- <PROFILE_HOME>: where the appserver instance resides. The default location is under "<WAS_HOME>/profiles".

- <OTHER_HOME>: any additional files that may reside outside of <WAS_HOME>. Examples include:
- shared library .jar files
- Resource Adapter .rar files
- Key and trust store files (.jks and .p12)
- Other files such as jdbc drivers

For Linux, use the command "find <directory> -user root" to find files owned by root user.

On windows use the "dir /Q /S" command from the root directories to show the owners of all files.

Examine the output for files owned by the administrator or root account.

If any WebSphere file or additional files as described above are owned by root or the administrator, this is a finding.'
  desc 'fix', 'Note: executing this fix without proper planning regarding file ownership can render your installation inoperable. See vulnerability discussion before executing this fix.

Ensure all WebSphere related files and folders are owned by the WebSphere OS user.

Ensure OS group membership is restricted.

File ownership changes for UNIX systems:
chown -R <user> <WAS_HOME>
chown -R <user> <PROFILE_HOME>, 
chown -R <user> <OTHER_HOME>, <OTHER_HOME> may be zero or more directories for other files

Group ownership changes for UNIX systems:
chgrp -R <user> <WAS_HOME>
chgrp -R <user> <PROFILE_HOME>,
chgrp -R <user> <OTHER_HOME>, where <OTHER_HOME> may be zero or more root directories for other files

File ownership changes for Windows systems:
"takeown /r /u <user> /f <directory /p <password of user>", where the <directory> is <WAS_HOME>, <PROFILE_HOME>, or <OTHER_HOME>'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81271'
  tag rid: 'SV-95985r1_rule'
  tag stig_id: 'WBSP-AS-000920'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-88051r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
