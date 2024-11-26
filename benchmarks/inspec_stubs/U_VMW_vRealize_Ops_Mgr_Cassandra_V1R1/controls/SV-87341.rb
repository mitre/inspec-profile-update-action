control 'SV-87341' do
  title 'The Cassandra Server must generate audit records when privileges/permissions are deleted.'
  desc "Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of individuals' and groups' privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, deleting permissions is typically done via the REVOKE or DENY command."
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when privileges/permissions are deleted.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records when privileges/permissions are deleted.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72709'
  tag rid: 'SV-87341r1_rule'
  tag stig_id: 'VROM-CS-000325'
  tag gtitle: 'SRG-APP-000499-DB-000330'
  tag fix_id: 'F-79113r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
