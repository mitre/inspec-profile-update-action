control 'SV-87303' do
  title 'The Cassandra Server must reveal detailed error messages only to the ISSO, ISSM, SA, and DBA.'
  desc %q(If the DBMS provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 

Some default DBMS error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. 

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant. 

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA and DBA. Other individuals or roles may be specified according to organization-specific needs, with DBA approval.)
  desc 'check', 'Review the Cassandra Server to ensure detailed error messages are only revealed to the ISSO, ISSM, SA and DBA.

At the command prompt, execute the following command:

# ls -l /usr/lib/vmware-vcops/user/conf/cassandra

If any file is not owned by "admin", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to only reveal detailed error messages to the ISSO, ISSM, SA and DBA.

At the command prompt, execute the following command:

# chown admin /usr/lib/vmware-vcops/user/conf/cassandra/<file>

Replace <file> with any file not owned by "admin".'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72827r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72671'
  tag rid: 'SV-87303r1_rule'
  tag stig_id: 'VROM-CS-000200'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-79075r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
