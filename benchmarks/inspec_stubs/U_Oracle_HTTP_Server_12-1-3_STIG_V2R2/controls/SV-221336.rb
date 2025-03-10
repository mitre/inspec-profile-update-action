control 'SV-221336' do
  title 'The log information from OHS must be protected from unauthorized deletion.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of audit records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized deletion. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from deletion by non-privileged users.'
  desc 'check', '1. Change to the ORACLE_HOME/user_projects/domains/base_domain/servers directory.

2. Execute the command: find . -name *.log 

3. Verify that each log file that was returned has the owner and group set to the user and group used to run the web server.  The user and group are typically set to Oracle.

4. Verify that each log file that was returned has the permissions on the log file set to "640" or more restrictive.

If the owner, group or permissions are set incorrectly on any of the log files, this is a finding.'
  desc 'fix', '1. Change to the ORACLE_HOME/user_projects/domains/base_domain/servers directory.

2. Execute the command: find . -name *.log 

3. Set the owner and group to the user and group used to run the web server.  The user and group are typically set to Oracle.

4. Set the permissions on all the log files returned to "640".'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23051r414691_chk'
  tag severity: 'medium'
  tag gid: 'V-221336'
  tag rid: 'SV-221336r879578_rule'
  tag stig_id: 'OH12-1X-000076'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag fix_id: 'F-23040r414692_fix'
  tag 'documentable'
  tag legacy: ['SV-78729', 'V-64239']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
