control 'SV-87263' do
  title 'The Cassandra database must initiate session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the DBMS is running."
  desc 'check', %q(Review the Cassandra Server configuration to ensure session auditing is initiated upon startup.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to initiate session auditing upon startup.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72631'
  tag rid: 'SV-87263r1_rule'
  tag stig_id: 'VROM-CS-000030'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-79033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
