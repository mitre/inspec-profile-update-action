control 'SV-24823' do
  title 'The DBMS host platform and other dependent applications should be configured in compliance with applicable STIG requirements.'
  desc 'The security of the data stored in the DBMS is also vulnerable to attacks against the host platform, calling applications, and other application or optional components.'
  desc 'check', 'If the DBMS host being reviewed is not a production DBMS host, this check is Not a Finding.

Review evidence of security hardening and auditing of the DBMS host platform with the IAO.

If the DBMS host platform has not been hardened and received a security audit, this is a Finding.

Review evidence of security hardening and auditing for all application(s) that store data in the database and all other separately configured components that access the database including web servers, application servers, report servers, etc.

If any have not been hardened and received a security audit, this is a Finding.

Review evidence of security hardening and auditing for all application(s) installed on the local DBMS host where security hardening and auditing guidance exists.

If any have not been hardened and received a security audit, this is a Finding.'
  desc 'fix', 'Configure all related application components and the DBMS host platform in accordance with the applicable DoD STIG.

Regularly audit the security configuration of related applications and the host platform to confirm continued compliance with security requirements.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29388r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15116'
  tag rid: 'SV-24823r1_rule'
  tag stig_id: 'DG0175-ORACLE11'
  tag gtitle: 'DBMS host and component STIG compliancy'
  tag fix_id: 'F-26414r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
