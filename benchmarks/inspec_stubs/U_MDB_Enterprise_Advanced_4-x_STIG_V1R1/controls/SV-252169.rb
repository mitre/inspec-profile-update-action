control 'SV-252169' do
  title 'MongoDB must reveal detailed error messages only to the ISSO, ISSM, SA, and DBA.'
  desc %q(If MongoDB provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Some default DBMS error messages can contain information that could aid an attacker in, among other things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information.

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant.

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA, and DBA. Other individuals or roles may be specified according to organization-specific needs, with appropriate approval.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.)
  desc 'check', 'A mongod or mongos running with security.redactClientLogData:true redacts any message accompanying a given log event before logging. 

This prevents the mongod or mongos from writing potentially sensitive data stored on the database to the diagnostic log. Metadata such as error or operation codes, line numbers, and source file names are still visible in the logs. 

To identify the level of information being displayed in the MongoDB logfiles run the following command:
 db.getSiblingDB("admin").runCommand({getCmdLineOpts: 1}).parsed.security.redactClientLogData

If the command does not return true this is a finding.

The MongoDB command getLog is an administrative command that will return the most recent 1024 logged mongod events. 

Ensure that application users are not authorized to execute this command. 

To validate this run the following command on the name of the application user to see actions its permitted to perform on the cluster resource:

 db.runCommand({usersInfo: %username%, showPrivileges: 1}).users[0].inheritedPrivileges.filter(privilege = privilege.resource.cluster)

If getLog appears in the list of actions, this is a finding.'
  desc 'fix', 'Edit the %MongoDB configuration file% (default location: /etc/mongod.conf) and add the following parameter redactClientLogData in the security section of that file:

security:
  redactClientLogData: true
  
Stop/start (restart) any mongod or mongos using the %MongoDB configuration file%.

Identify and remove any administrative roles and privileges from application users.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55625r813887_chk'
  tag severity: 'medium'
  tag gid: 'V-252169'
  tag rid: 'SV-252169r813889_rule'
  tag stig_id: 'MD4X-00-004300'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-55575r813888_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
