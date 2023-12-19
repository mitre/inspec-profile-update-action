control 'SV-251192' do
  title 'Redis Enterprise DBMS must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to the DBMS that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and non-standard sources.'
  desc 'check', 'All local access to the server is handled by the underlying RHEL OS server that hosts the Redis Enterprise DBMS and is viewable in syslog. Additionally, RHEL can be configured to audit direct access to Redis Enterprise by modifying the rule set in /etc/audit/audit.rules to include the redis-cli and rladmin command found in /opt/redislabs/bin. 

To determine if the OS is auditing direct and privileged access/execution of the database and database configuration options on the server:
cat to /etc/audit/audit.rules 

Examine the audit rules defined for rules that specify that command calls for /opt/redislabs/bin/redis-cli and /opt/redislabs/bin/rladmin are audited, if not present, this is a finding.'
  desc 'fix', 'Configure the host RHEL OS to generate audit records whenever a user calls the redis-cli command. This can be done by adding a rule to the /etc/audit/audit.rules to generate records when /opt/redislabs/bin/redis-cli and /opt/redislabs/bin/rladmin is called.

Example Linux commands:
-a always,exit -F path=/opt/redislabs/bin/redis-cli -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
-a always,exit -F path=/opt/redislabs/bin/rladmin -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54627r804764_chk'
  tag severity: 'medium'
  tag gid: 'V-251192'
  tag rid: 'SV-251192r804766_rule'
  tag stig_id: 'RD6X-00-004400'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag fix_id: 'F-54581r804765_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
