control 'SV-238460' do
  title 'The DBMS must disable user accounts after 35 days of inactivity.'
  desc 'Attackers that are able to exploit an inactive DBMS account can potentially obtain and maintain undetected access to the database. 

Owners of inactive DBMS accounts will not notice if unauthorized access to their user account has been obtained. All DBMS need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise.
 
To address access requirements, some database administrators choose to integrate their databases with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the database administrator to off-load those access control functions and focus on core application features and functionality. 

This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are local logon administrator accounts used by system administrators when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP This requirement applies to cases where it is necessary to have accounts directly managed by Oracle'
  desc 'check', 'If all user accounts are managed and authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

For accounts managed by Oracle, check DBMS settings to determine if accounts can be automatically disabled by the system after 35 days of inactivity. Also, ask the DBA if an alternative method, such as a stored procedure run daily, to disable Oracle-managed accounts inactive for more than 35 days, has been deployed. 

If the ability to disable accounts after 35 days of inactivity, by either of these means, does not exist, this is a finding.'
  desc 'fix', "For accounts managed by Oracle, create a script or store procedure that runs once a day.

Write a SQL statement to determine accounts that have not logged in within 35 days:
 
Example:
select username from dba_audit_trail where  action_name = 'LOGON'
group  by username having max(timestamp) < sysdate - 36

And then disable all accounts that have not logged in within 35 days."
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41671r667552_chk'
  tag severity: 'medium'
  tag gid: 'V-238460'
  tag rid: 'SV-238460r667554_rule'
  tag stig_id: 'O112-C2-013800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41630r667553_fix'
  tag 'documentable'
  tag legacy: ['V-52269', 'SV-66485']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
