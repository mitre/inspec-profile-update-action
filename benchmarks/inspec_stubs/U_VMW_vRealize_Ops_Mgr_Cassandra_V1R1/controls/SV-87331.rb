control 'SV-87331' do
  title 'The Cassandra Server must generate audit records when unsuccessful attempts to add privileges/permissions occur.'
  desc "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict individuals' and groups' privileges could go undetected. 

In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when unsuccessful attempts to add privileges/permissions occur.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records when unsuccessful attempts to add privileges/permissions occur.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72855r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72699'
  tag rid: 'SV-87331r1_rule'
  tag stig_id: 'VROM-CS-000290'
  tag gtitle: 'SRG-APP-000495-DB-000327'
  tag fix_id: 'F-79103r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
