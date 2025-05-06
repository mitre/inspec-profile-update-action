control 'SV-87265' do
  title 'The Cassandra database must produce audit records containing sufficient information to establish what type of events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.'
  desc 'check', 'Review the Cassandra Server settings to ensure audit records containing sufficient information to establish what type of events occurred are produced.

Navigate to and open /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml.

Navigate to the <appender> node with the name="FILE" attribute.

Navigate to <encoder> node.

If the <pattern> node does not look like the expected result, this is a finding.

Expected result:
<pattern>%-5level [%thread] %date{ISO8601, UTC} %F:%L - %msg%n</pattern>'
  desc 'fix', 'Configure the Cassandra Server to produce audit records containing sufficient information to establish what type of events occurred.

Navigate to and open /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml.

Navigate to the <appender> node with the name="FILE" attribute.

Navigate to <encoder> node.

Edit the <pattern> to look like the below.
<pattern>%-5level [%thread] %date{ISO8601, UTC} %F:%L - %msg%n</pattern>'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72633'
  tag rid: 'SV-87265r1_rule'
  tag stig_id: 'VROM-CS-000040'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag fix_id: 'F-79035r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
