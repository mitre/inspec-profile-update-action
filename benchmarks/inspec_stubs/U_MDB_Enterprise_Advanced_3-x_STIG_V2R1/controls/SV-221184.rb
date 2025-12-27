control 'SV-221184' do
  title 'MongoDB must reveal detailed error messages only to the ISSO, ISSM, SA, and DBA.'
  desc %q(If MongoDB provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Some default DBMS error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information.

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant.

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA, and DBA. Other individuals or roles may be specified according to organization-specific needs, with appropriate approval.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.)
  desc 'check', 'A mongod or mongos running with "security.redactClientLogData" redacts any message accompanying a given log event before logging. 

This prevents the mongod or mongos from writing potentially sensitive data stored on the database to the diagnostic log. Metadata such as error or operation codes, line numbers, and source file names are still visible in the logs.

Verify that the MongoDB configuration file (default location: /etc/mongod.conf) contains the following:

security:
redactClientLogData: "true"

If this parameter is not present, this is a finding.'
  desc 'fix', 'Edit the MongoDB configuration file (default location: /etc/mongod.conf) and add the following parameter "redactClientLogData" in the security section of that file:

security:
redactClientLogData: "true"

Stop/start (restart) any mongod or mongos using the MongoDB configuration file.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22899r411046_chk'
  tag severity: 'medium'
  tag gid: 'V-221184'
  tag rid: 'SV-221184r411048_rule'
  tag stig_id: 'MD3X-00-000530'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-22888r411047_fix'
  tag 'documentable'
  tag legacy: ['SV-96609', 'V-81895']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
