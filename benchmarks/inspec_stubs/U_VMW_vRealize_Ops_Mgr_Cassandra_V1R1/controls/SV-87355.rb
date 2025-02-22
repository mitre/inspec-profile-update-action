control 'SV-87355' do
  title 'The Cassandra Server must be able to generate audit records when successful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when successful accesses to objects occur.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records when successful accesses to objects occur.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72723'
  tag rid: 'SV-87355r1_rule'
  tag stig_id: 'VROM-CS-000365'
  tag gtitle: 'SRG-APP-000507-DB-000356'
  tag fix_id: 'F-79127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
