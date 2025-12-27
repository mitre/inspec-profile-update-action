control 'SV-87357' do
  title 'The Cassandra Server must generate audit records when unsuccessful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DELETE
EXECUTE

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when unsuccessful accesses to objects occur.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records when unsuccessful accesses to objects occur.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72725'
  tag rid: 'SV-87357r1_rule'
  tag stig_id: 'VROM-CS-000370'
  tag gtitle: 'SRG-APP-000507-DB-000357'
  tag fix_id: 'F-79129r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
