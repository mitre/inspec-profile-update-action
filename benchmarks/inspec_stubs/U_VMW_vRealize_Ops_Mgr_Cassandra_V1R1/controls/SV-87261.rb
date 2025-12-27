control 'SV-87261' do
  title 'The Cassandra database must be able to generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(Review the Cassandra Server settings to ensure that audit records can be produced when the system denies or fails to complete attempts to retrieve privileges/permissions/role membership.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to produce audit records when other errors prevent access to privileges/permissions/role membership.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72629'
  tag rid: 'SV-87261r1_rule'
  tag stig_id: 'VROM-CS-000025'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag fix_id: 'F-79031r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
