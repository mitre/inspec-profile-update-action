control 'SV-87339' do
  title 'The Cassandra Server must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Review the Cassandra Server configuration to ensure audit records are generated when unsuccessful attempts to modify security objects occur.

Open console to the server, Cassandra DB is hosted at, and type: "find / | grep "logback.xml"". Open "logback.xml" file and review "level" parameter value under <root />.

If level is not set to "ALL", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to generate audit records when unsuccessful attempts to modify security objects occur.

Open console to the server, Cassandra DB is hosted at, and type: "find / | grep "logback.xml"". Open "logback.xml" file and set "level" parameter value under <root /> to "ALL".'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72707'
  tag rid: 'SV-87339r1_rule'
  tag stig_id: 'VROM-CS-000310'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-79111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
