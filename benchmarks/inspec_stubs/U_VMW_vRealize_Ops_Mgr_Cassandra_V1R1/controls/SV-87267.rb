control 'SV-87267' do
  title 'The Cassandra database must produce audit records containing time stamps to establish when the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the date and time when events occurred.

Associating the date and time with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly when specific actions were performed. This requires the date and time an audit record is referring to. If date and time information is not recorded and stored with the audit record, the record itself is of very limited use.'
  desc 'check', 'Review the Cassandra Server setting to ensure audit records containing time stamps to establish when the events occurred are produced.

Navigate to and open /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml.

Navigate to the <appender> node with the name="FILE" attribute.

Navigate to <encoder> node.

If the <pattern> node does not look like the expected result, this is a finding.

Expected result:
<pattern>%-5level [%thread] %date{ISO8601, UTC} %F:%L - %msg%n</pattern>'
  desc 'fix', 'Configure the Cassandra Server to produce audit records containing time stamps to establish when the events occurred.

Navigate to and open /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml.

Navigate to the <appender> node with the name="FILE" attribute.

Navigate to <encoder> node.

Edit the <pattern> to look like the below.
<pattern>%-5level [%thread] %date{ISO8601, UTC} %F:%L - %msg%n</pattern>'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72635'
  tag rid: 'SV-87267r1_rule'
  tag stig_id: 'VROM-CS-000045'
  tag gtitle: 'SRG-APP-000096-DB-000040'
  tag fix_id: 'F-79037r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
