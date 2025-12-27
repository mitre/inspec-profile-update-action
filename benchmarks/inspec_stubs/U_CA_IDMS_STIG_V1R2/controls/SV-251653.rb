control 'SV-251653' do
  title 'The DBMS must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to be carefully considered by the organization and development team.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, usernames, and other system information not required for troubleshooting but very useful to someone targeting the system.

Carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, Social Security numbers, and credit card numbers.'
  desc 'check', 'Consult the system DBA and review system procedures for WTO exits that modify IDMS messages that go to non-privileged users. 

If there is no procedure, this is a finding.'
  desc 'fix', "Develop an IDMS user exit WTOEXIT to review, alter, redirect and suppress text of IDMS messages written to the operator's console. (Note that some system messages are written to the DC/UCF log as they are originally issued. Some system messages are written only to the console, regardless of how they are defined in the message dictionary)."
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55088r807824_chk'
  tag severity: 'medium'
  tag gid: 'V-251653'
  tag rid: 'SV-251653r808357_rule'
  tag stig_id: 'IDMS-DB-000920'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-55042r807825_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
