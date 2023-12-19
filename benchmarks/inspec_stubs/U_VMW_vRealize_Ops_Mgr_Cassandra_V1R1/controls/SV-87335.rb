control 'SV-87335' do
  title 'The Cassandra Server must generate audit records when unsuccessful attempts to modify privileges/permissions occur.'
  desc "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict individuals' and groups' privileges could go undetected. 

In an SQL environment, modifying permissions is typically done via the GRANT, REVOKE, and DENY commands. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when unsuccessful attempts to modify privileges/permissions occur.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', "Configure the Cassandra Server to generate audit records when unsuccessful attempts to modify privileges/permissions occur.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml"
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72703'
  tag rid: 'SV-87335r1_rule'
  tag stig_id: 'VROM-CS-000300'
  tag gtitle: 'SRG-APP-000495-DB-000329'
  tag fix_id: 'F-79107r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
