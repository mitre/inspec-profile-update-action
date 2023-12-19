control 'SV-87337' do
  title 'The Cassandra Server must generate audit records when security objects are modified.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.'
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when security objects are modified.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records when security objects are modified.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72705'
  tag rid: 'SV-87337r1_rule'
  tag stig_id: 'VROM-CS-000305'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag fix_id: 'F-79109r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
