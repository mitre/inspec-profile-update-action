control 'SV-24850' do
  title 'Access to the Oracle SYS and SYSTEM accounts should be restricted to authorized DBAs.'
  desc 'The Oracle SYS account has all database privileges assigned to it (SYSDBA). This account is used to manage the database availability status (startup and shutdown). The SYS account is used by any DBMS account that connects to the database with SYSDBA privileges. Direct use of the SYS account does not provide a level of individual accountability for actions taken during its use and does not provide individual accountability. To preserve accountability, direct access to the SYS account should be logged manually and its use monitored closely.'
  desc 'check', 'Review the policy and procedures for use of the Oracle default accounts including direct use of the Oracle SYS and SYSTEM accounts with the IAO and DBA.

If a policy does not exist for their use, this is a Finding.

If procedures, automated or manual, for logging default account use are not defined or implemented, this is a Finding.

If monitoring use of default accounts do not exist or is not implemented, this is a Finding.'
  desc 'fix', 'Design, document and implement policy and procedures for use, logging and monitoring of Oracle default accounts in the System Security Plan.

Ensure those granted access to the accounts are aware of the accounts and the policies and procedures for them.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29409r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2511'
  tag rid: 'SV-24850r1_rule'
  tag stig_id: 'DO0140-ORACLE11'
  tag gtitle: 'Oracle default account access'
  tag fix_id: 'F-26436r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
