control 'SV-238439' do
  title 'The DBMS must restrict grants to sensitive information to authorized user roles.'
  desc 'Applications employ the concept of least privilege for specific duties and information systems (including specific functions, ports, protocols, and services). The concept of least privilege is also applied to information system processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and information system accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of information systems.

Unauthorized access to sensitive data may compromise the confidentiality of personnel privacy, threaten national security, or compromise a variety of other sensitive operations. Access controls are best managed by defining requirements based on distinct job functions and assigning access based on the job function assigned to the individual user.'
  desc 'check', 'Obtain a list of privileges assigned to user accounts. If access to sensitive information is granted to roles not authorized to access sensitive information, this is a finding.

If access to sensitive information is granted to individual accounts rather than to a role, this is a finding.'
  desc 'fix', 'Define application user roles based on privilege and job function requirements. 

Assign the required privileges to the role and assign the role to authorized application user accounts.

Revoke any privileges to sensitive information directly assigned to application user accounts.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41650r667489_chk'
  tag severity: 'medium'
  tag gid: 'V-238439'
  tag rid: 'SV-238439r667491_rule'
  tag stig_id: 'O112-C2-003500'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-41609r667490_fix'
  tag 'documentable'
  tag legacy: ['V-52371', 'SV-66587']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
