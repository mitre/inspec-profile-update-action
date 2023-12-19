control 'SV-87259' do
  title 'The Cassandra database must be able to generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.'
  desc 'check', %q(Review the Cassandra Server settings to ensure that audit records can be produced when privileges/permissions/role memberships are retrieved.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to produce audit records when privileges/permissions/role memberships are retrieved.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72627'
  tag rid: 'SV-87259r1_rule'
  tag stig_id: 'VROM-CS-000020'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-79029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
