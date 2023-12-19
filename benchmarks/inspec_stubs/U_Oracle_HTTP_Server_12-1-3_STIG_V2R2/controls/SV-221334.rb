control 'SV-221334' do
  title 'OHS log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.'
  desc 'check', '1. Change to the ORACLE_HOME/user_projects/domains/base_domain/servers directory.

2. Execute the command: find . -name *.log 

3. Verify that each log file that was returned has the owner and group set to the user and group used to run the web server.  The user and group are typically set to Oracle.

4. Verify that each log file that was returned has the permissions on the log file set to "640" or more restrictive.

If the owner, group or permissions are set incorrectly on any of the log files, this is a finding.'
  desc 'fix', '1. Change to the ORACLE_HOME/user_projects/domains/base_domain/servers directory.

2. Execute the command: find . -name *.log
 
3. Set the owner and group to the user and group used to run the web server. The user and group are typically set to Oracle.

4. Set the permissions on all the log files returned to "640".'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23049r414685_chk'
  tag severity: 'medium'
  tag gid: 'V-221334'
  tag rid: 'SV-221334r879576_rule'
  tag stig_id: 'OH12-1X-000074'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-23038r414686_fix'
  tag 'documentable'
  tag legacy: ['SV-78725', 'V-64235']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
