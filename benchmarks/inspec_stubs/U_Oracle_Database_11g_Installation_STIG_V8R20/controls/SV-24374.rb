control 'SV-24374' do
  title 'The DBMS software installation account should be restricted to authorized users.'
  desc 'DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a greater impact on database security and operation.  It is especially important to grant access to privileged accounts to only those persons who are qualified and authorized to use them.'
  desc 'check', 'Review documented and implemented procedures for controlling and granting access to the Oracle DBMS software installation account.

If access or use of this account is not restricted to the minimum number of personnel required, or unauthorized access to the account has been granted, this is a Finding.

On UNIX systems:
  If the account is not disabled when not in use, and not configured to prevent direct logon, this is a Finding.

On Windows systems:
The Oracle DBMS software is usually installed using an account with administrator privileges. Ownership is assigned to the account used to install the DBMS software. 

The creation of a dedicated Oracle OS account and change of ownership of all files in the %ORACLE_HOME% and %ORACLE_BASE% directories and subdirectories should be performed prior to placing the DBMS system into production. See checks DG0019, DO0120 and DG0102 for details on establishing a dedicated OS account for Oracle services on Windows platforms.'
  desc 'fix', 'Develop, document and implement procedures to restrict use of the Oracle DBMS software installation account.

Unix environments:
Ensure that the Oracle DBMS software installation account is disabled when not in use, except in cases where this would interfere with required functionality.  In such cases, prevent direct logon as the Oracle DBMS software installation account by locking its password; authorize the appropriate administrative users to operate as the Oracle DBMS software installation account via the "su" or "sudo" command.

Other environments:
Ensure that the Oracle DBMS software installation account is disabled when not in use.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29113r3_chk'
  tag severity: 'medium'
  tag gid: 'V-2422'
  tag rid: 'SV-24374r2_rule'
  tag stig_id: 'DG0040-ORACLE11'
  tag gtitle: 'DBMS software owner account access'
  tag fix_id: 'F-26116r3_fix'
  tag responsibility: 'Information Assurance Officer'
end
