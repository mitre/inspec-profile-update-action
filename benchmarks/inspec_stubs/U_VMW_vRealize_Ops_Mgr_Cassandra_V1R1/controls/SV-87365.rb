control 'SV-87365' do
  title 'The Cassandra Server must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', 'Review the Cassandra Server to ensure audit data is off-loaded to a separate log management facility.

At the command prompt, execute the following command:

# grep SyslogAppender /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to off-load audit data to a separate log management facility.

Navigate to and open /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml.

Navigate to the <configuration> node.

Add the following <appender> node to the <configuration> node.

  <appender name="SYSLOG" class="ch.qos.logback.classic.net.SyslogAppender">
    <syslogHost>syslogServerHostName</syslogHost>
    <facility>AUTH</facility>
    <suffixPattern>%-5level [%thread] %date{ISO8601, UTC} %F:%L - %msg%n </suffixPattern>
  </appender>

Navigate to the <root> node.

Add the following to the <root> node.
    <appender-ref ref="SYSLOG" />'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72889r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72733'
  tag rid: 'SV-87365r1_rule'
  tag stig_id: 'VROM-CS-000390'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-79153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
