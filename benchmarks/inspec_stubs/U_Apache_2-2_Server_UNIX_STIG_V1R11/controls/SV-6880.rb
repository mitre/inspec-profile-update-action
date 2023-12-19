control 'SV-6880' do
  title 'The access control files are owned by a privileged web server account.'
  desc 'This check verifies that the key web server system configuration files are owned by the SA or Web Manager controlled account. These same files which control the configuration of the web server, and thus its behavior, must also be accessible by the account which runs the web service. If these files are altered by a malicious user, the web server would no longer be under the control of its managers and owners; properties in the web server configuration could be altered to compromise the entire server platform.'
  desc 'check', 'This check verifies that the SA or Web Manager controlled account owns the key web server files. These same files, which control the configuration of the web server, and thus its behavior, must also be accessible by the account that runs the web service process. 

If it exists, the following file need to be owned by a privileged account.

.htaccess
httpd.conf

Use the command find / -name httpd.conf to find the file
Change to the Directory that contains the httpd.conf file
Use the command ls -l httpd.conf to determine ownership of the file

-The Web Manager or the SA should own all the system files and directories. 
-The configurable directories can be owned by the WebManager or equivalent user.  

Permissions on these files should be 660 or more restrictive.

If root or an authorized user does not own the web system files and the permission are not correct, this is a finding.'
  desc 'fix', 'The site needs to ensure that the owner should be the non-privileged web server account or equivalent which runs the web service; however, the group permissions represent those of the user accessing the web site that must execute the directives in .htacces.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-2677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2256'
  tag rid: 'SV-6880r1_rule'
  tag stig_id: 'WG280'
  tag gtitle: 'WG280'
  tag fix_id: 'F-6761r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
