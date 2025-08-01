control 'SV-213563' do
  title 'The EDB Postgres Advanced Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access the DBMS. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', 'Review the system documentation to determine the required levels of protection for DBMS server securables by type of login.

Review the permissions actually in place on the server. 

If the actual permissions do not match the documented requirements, this is a finding.'
  desc 'fix', 'Use GRANT, REVOKE, ALTER statements to add and remove permissions on server-level securables, bringing them into line with the documented requirements.'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14785r290001_chk'
  tag severity: 'high'
  tag gid: 'V-213563'
  tag rid: 'SV-213563r836837_rule'
  tag stig_id: 'PPS9-00-000800'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-14783r290002_fix'
  tag 'documentable'
  tag legacy: ['SV-83483', 'V-68879']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
