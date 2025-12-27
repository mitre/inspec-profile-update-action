control 'SV-214267' do
  title 'The Apache web server must be protected from being stopped by a non-privileged user.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a denial of service (DoS), and the second is to put in place changes the attacker made to the web server configuration.

To prohibit an attacker from stopping the Apache web server, the process ID (pid) of the web server and the utilities used to start/stop it must be protected from access by non-privileged users. By knowing the "pid" and having access to the Apache web server utilities, a non-privileged user has a greater capability of stopping the server, whether intentionally or unintentionally.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine where the process ID is stored and which utilities are used to start/stop the web server.

Locate the httpd.pid file and list its permission set and owner/group

# find / -name “httpd.pid
Output should be similar to: /run/httpd/httpd.pid 

# ls -laH /run/httpd/httpd.pid
Output should be similar -rw-r--r--. 1 root root 5 Jun 13 03:18 /run/httpd/httpd.pid

If the file owner/group is not an administrative service account, this is a finding.

If permission set is not 644 or more restrictive, this is a finding.
 
Verify the Apache service utilities (binaries) have the correct permission set and are user/group owned by an administrator account

# ls -laH /usr/sbin/service
Output should be similar: -rwxr-xr-x. 1 root root 3.2K Aug 19, 2019 /usr/sbin/service

# ls -laH /usr/sbin/apachectl
Output should be similar: -rwxr-xr-x. 1 root root 4.2K Oct 8, 2019 /usr/sbin/apachectl
 
If the service utilities owner/group is not an administrative service account, this is a finding.
 
If permission set is not 755 or more restrictive, this is a finding.'
  desc 'fix', %q(Review the web server documentation and deployed configuration to determine where the process ID is stored and which utilities are used to start/stop the web server.

Determine where the "httpd.pid" file is located by running the following command:

find / -name "httpd.pid"

Run the following commands:
 
# cd <'httpd.pid location'>/
# chown <'service account'> httpd.pid 
# chmod 644 httpd.pid 
# cd /usr/sbin 
# chown <'service account'> service apachectl 
# chmod 755 service apachectl)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15481r881457_chk'
  tag severity: 'medium'
  tag gid: 'V-214267'
  tag rid: 'SV-214267r881458_rule'
  tag stig_id: 'AS24-U1-000820'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-15479r277062_fix'
  tag 'documentable'
  tag legacy: ['V-92731', 'SV-102819']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
