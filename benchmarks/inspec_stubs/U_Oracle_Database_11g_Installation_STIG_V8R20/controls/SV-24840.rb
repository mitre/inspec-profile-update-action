control 'SV-24840' do
  title 'Privileges assigned to developers on shared production and development DBMS hosts and the DBMS should be monitored every three months or more frequently for unauthorized changes.'
  desc 'The developer role does not include need-to-know or administrative privileges to production databases. Assigning excess privileges can lead to unauthorized access to sensitive data or compromise of database operations.'
  desc 'check', 'If the DBMS or DBMS host is not shared by production and development activities, this check is Not a Finding.

Review policy and procedures documented or noted in the System Security Plan and evidence of monitoring of developer privileges on shared development and production DBMS and DBMS host systems.

If developer privileges are not monitored every three months or more frequently, this is a Finding.

NOTE: Though shared production/non-production DBMS installations was allowed under previous database STIG guidance, doing so may place it in violation of OS, Application, Network or Enclave STIG guidance. Ensure that any shared production/non-production DBMS installations meets STIG guidance requirements at all levels or mitigate any conflicts in STIG guidance with your DAA.'
  desc 'fix', 'Develop, document and implement procedures to monitor DBMS and DBMS host privileges assigned to developers on shared production and development systems to detect unauthorized assignments every three months or more often.

Recommend establishing a dedicated DBMS host for production DBMS installations (See Checks DG0109 and DG0110). A dedicated host system in this case refers to an instance of the operating system at a minimum. The operating system may reside on a virtual host machine where supported by the DBMS vendor.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29401r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15108'
  tag rid: 'SV-24840r1_rule'
  tag stig_id: 'DG0194-ORACLE11'
  tag gtitle: 'DBMS developer privilege monitoring on shared DBMS'
  tag fix_id: 'F-26426r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
