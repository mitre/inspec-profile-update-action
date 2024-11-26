control 'SV-87325' do
  title 'The Cassandra Server must be able to generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when security objects are accessed.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records when security objects are accessed.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72693'
  tag rid: 'SV-87325r1_rule'
  tag stig_id: 'VROM-CS-000265'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag fix_id: 'F-79097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
