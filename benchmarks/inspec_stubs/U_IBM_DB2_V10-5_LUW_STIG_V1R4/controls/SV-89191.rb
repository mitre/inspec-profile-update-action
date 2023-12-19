control 'SV-89191' do
  title 'DB2 must reveal detailed error messages only to the ISSO, ISSM, SA and DBA.'
  desc %q(If the DBMS provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 

Some default DBMS error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. 

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant. 

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA and DBA. Other individuals or roles may be specified according to organization-specific needs, with DBA approval.

This calls for the review of applications, which will require collaboration with the application developers. It is recognized that in many cases the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue is addressed, and must document what has been discovered.)
  desc 'check', 'Check DB2 settings and custom database code to determine if detailed error messages are ever displayed to unauthorized individuals.

If detailed error messages are displayed to individuals not authorized to view them, this is a finding.'
  desc 'fix', 'Configure DB2 settings, custom database code, and associated application code not to display detailed error messages to those not authorized to view them.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74443r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74517'
  tag rid: 'SV-89191r1_rule'
  tag stig_id: 'DB2X-00-006300'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-81117r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
