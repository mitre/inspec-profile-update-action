control 'SV-100033' do
  title 'The vRA PostgreSQL error file must be protected from unauthorized access.'
  desc %q(If the DBMS provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 

Some default DBMS error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. 

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant. 

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA and DBA. Other individuals or roles may be specified according to organization-specific needs, with DBA approval.)
  desc 'check', 'At the command prompt, execute the following command:

# ls -l /storage/db/pgdata/serverlog

If the file permissions are more permissive than "600", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chmod 600 /storage/db/pgdata/serverlog'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89075r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89383'
  tag rid: 'SV-100033r1_rule'
  tag stig_id: 'VRAU-PG-000250'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-96125r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
