control 'SV-239802' do
  title 'The vROps PostgreSQL DB must reveal detailed error messages only to the ISSO, ISSM, SA and DBA.'
  desc %q(If the DBMS provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 

Some default DBMS error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. 

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant. 

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA and DBA. Other individuals or roles may be specified according to organization-specific needs, with DBA approval.)
  desc 'check', 'At the command prompt, execute the following command:

# ls -l /storage/db/vcops/vpostgres/data/serverlog

If the file permissions are more permissive than "640", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chmod 640 /storage/db/vcops/vpostgres/data/serverlog'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43035r663781_chk'
  tag severity: 'medium'
  tag gid: 'V-239802'
  tag rid: 'SV-239802r879656_rule'
  tag stig_id: 'VROM-PG-000305'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-42994r663782_fix'
  tag 'documentable'
  tag legacy: ['SV-98927', 'V-88277']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
