control 'SV-87345' do
  title 'The Cassandra Server must generate audit records when security objects are deleted.'
  desc "The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an event occurs, it must be logged."
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when security objects are deleted.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records when security objects are deleted.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72713'
  tag rid: 'SV-87345r1_rule'
  tag stig_id: 'VROM-CS-000335'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag fix_id: 'F-79117r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
