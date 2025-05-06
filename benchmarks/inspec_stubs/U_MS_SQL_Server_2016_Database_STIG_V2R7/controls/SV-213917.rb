control 'SV-213917' do
  title 'SQL Server must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to be carefully considered by the organization and development team.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.

Carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Review application behavior and custom database code (stored procedures, triggers), to determine whether error messages contain information beyond what is needed for explaining the issue to general users.

If database error messages contain PII data, sensitive business data, or information useful for identifying the host system or database structure, this is a finding.'
  desc 'fix', 'Adjust database code to remove any information not required for explaining the error to an end user.

Consider enabling trace flag 3625 to mask certain system-level error information returned to non-administrative users.

Launch SQL Server Configuration Manager >> Click SQL Services >> Open the instance properties >> Click the Service Parameters tab >> Enter "-T3625" >> Click Add >> Click OK >> Restart SQL instance.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15135r313183_chk'
  tag severity: 'medium'
  tag gid: 'V-213917'
  tag rid: 'SV-213917r879655_rule'
  tag stig_id: 'SQL6-D0-002400'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-15133r313184_fix'
  tag 'documentable'
  tag legacy: ['SV-93803', 'V-79097']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
