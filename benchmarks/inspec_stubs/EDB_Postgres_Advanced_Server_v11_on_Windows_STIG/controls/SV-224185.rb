control 'SV-224185' do
  title 'The EDB Postgres Advanced Server must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages must be carefully considered by the organization and development team.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.

Carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Check custom database code to verify that error messages do not contain information beyond what is needed for troubleshooting the issue.

If custom database errors contain PII data, sensitive business data, or information useful for identifying the host system or database structure, this is a finding.'
  desc 'fix', 'Configure custom database code and associated application code not to divulge sensitive information or information useful for system identification in error messages.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25858r495573_chk'
  tag severity: 'medium'
  tag gid: 'V-224185'
  tag rid: 'SV-224185r508023_rule'
  tag stig_id: 'EP11-00-006500'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-25846r495574_fix'
  tag 'documentable'
  tag legacy: ['SV-109497', 'V-100393']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
