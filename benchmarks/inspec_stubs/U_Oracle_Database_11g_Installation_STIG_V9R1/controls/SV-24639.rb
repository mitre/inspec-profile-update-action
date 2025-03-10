control 'SV-24639' do
  title 'Procedures for establishing temporary passwords that meet DoD password requirements for new accounts should be defined, documented and implemented.'
  desc 'New accounts authenticated by passwords that are created without a password or with an easily guessed password are vulnerable to unauthorized access. Procedures for creating new accounts with passwords should include the required assignment of a temporary password to be modified by the user upon first use.'
  desc 'check', 'If all database accounts are configured to authenticate using certificates or other credentials besides passwords, this check is Not a Finding.

Review documented procedures and evidence of implementation for assignment of temporary passwords for password-authenticated accounts.

Confirm temporary passwords meet DoD password requirements.

Review documented procedures for distribution of temporary passwords to users.

Have the DBA demonstrate that the DBMS or applications accessing the database are configured to require a change of password by the user upon first use.

If documented procedures and evidence do not exist or are not complete, temporary passwords do not meet DoD password requirements, or the DBMS or applications accessing the database are not configured to require a change of password by the user upon first use, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures for assigning, distributing and changing of temporary passwords for new database user accounts.

Procedures should include instruction that meet current DoD password length and complexity requirements and provide a secure method to relay the temporary password to the user.

Temporary passwords should also be short-lived and require immediate update by the user upon first use.

Consider using account authentication using certificates or other credentials in place of password authentication.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29163r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3811'
  tag rid: 'SV-24639r1_rule'
  tag stig_id: 'DG0066-ORACLE11'
  tag gtitle: 'DBMS temporary password procedures'
  tag fix_id: 'F-26175r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
