control 'SV-40832' do
  title 'Access to the web server log files must be restricted to Administrators, the user assigned to run the web server software, Web Manager, and Auditors.'
  desc 'A major tool in exploring the web site use, attempted use, unusual conditions and problems are the access and error logs. In the event of a security incident, these logs can provide the SA and Web Manager with valuable information. Because of the information that is captured in the logs, it is critical that only authorized individuals have access to the logs.'
  desc 'check', 'Determine permissions for log files

Find the httpd.conf configuration file to determine the location of the log files. The location is indicated at the "ServerRoot" directive. The log directory is a sub-directory under the ServerRoot. 

ex. :\\Apache Group\\Apache2\\logs or :\\Apache Software Foundation\\Apache2.2\\logs

After locating the logs, use the Explorer to move to these files and examine their properties: 

Properties >> Security >> Permissions. 

Administrators: Read
Auditors: Full Control
Web Managers: Read
WebServer Account: Read/Write/Execute

If anyone other than the Auditors, Administrators, Web Managers, or the account that runs the web server has access to the log files, this is a finding.'
  desc 'fix', 'To ensure the integrity of the data that is being captured in the log files, ensure that only the members of the Auditors group, Administrators, and the user assigned to run the web server software is granted permissions to read the log files.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-35802r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13689'
  tag rid: 'SV-40832r1_rule'
  tag stig_id: 'WG255 W22'
  tag gtitle: 'WG255'
  tag fix_id: 'F-31043r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
  tag ia_controls: 'ECTP-1'
end
