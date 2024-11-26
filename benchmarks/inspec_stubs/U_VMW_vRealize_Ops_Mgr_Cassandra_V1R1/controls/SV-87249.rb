control 'SV-87249' do
  title 'The Cassandra database must produce audit records containing sufficient information to establish the outcome (success or failure) of the events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', %q(Review the Cassandra Server settings to ensure audit records containing sufficient information to establish the outcome (success or failure) of the events are produced.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to produce audit records containing sufficient information to establish the outcome (success or failure) of the events.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72771r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72617'
  tag rid: 'SV-87249r1_rule'
  tag stig_id: 'VROM-CS-000050'
  tag gtitle: 'SRG-APP-000099-DB-000043'
  tag fix_id: 'F-79019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
