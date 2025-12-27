control 'SV-252168' do
  title 'MongoDB must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to be carefully considered by the organization and development team.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.

Carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Check custom application code to verify that error messages do not contain information beyond what is needed for troubleshooting the issue.

If custom application error messages contain PII data, sensitive business data, or information useful for identifying the host system or database structure, this is a finding.

For example, when attempting to login using the MongoDB shell with incorrect client credentials, the user will receive a generic error message that the authentication failed regardless of whether the user exists or not.

If a user is attempting to perform an operation using the MongoDB shell for which they do not have privileges, MongoDB will return a generic error message that the operation is not authorized.

To identify the level of information being displayed in the MongoDB logfiles, run the following command:

 db.getSiblingDB("admin").runCommand({getCmdLineOpts: 1}).parsed.security.redactClientLogData

If the command does not return true, this is a finding.'
  desc 'fix', 'Configure custom application code so as not to divulge sensitive information or information useful for system identification in custom application error messages.

To configure MongoDB to redact client information from its log file do the following:

Edit the %MongoDB configuration file% (default location: /etc/mongod.conf)

Add the following option to the security section:

security:
   redactClientLogData: true 

Restart the MongoDB server from the operating system:

 sudo service mongod restart'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55624r813884_chk'
  tag severity: 'medium'
  tag gid: 'V-252168'
  tag rid: 'SV-252168r813886_rule'
  tag stig_id: 'MD4X-00-004200'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-55574r813885_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
