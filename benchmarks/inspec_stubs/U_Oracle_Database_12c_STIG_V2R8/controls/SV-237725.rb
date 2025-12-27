control 'SV-237725' do
  title 'The DBMS must disable user accounts after 35 days of inactivity.'
  desc 'Attackers that are able to exploit an inactive DBMS account can potentially obtain and maintain undetected access to the database. 

Owners of inactive DBMS accounts will not notice if unauthorized access to their user account has been obtained. All DBMS need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise.
 
To address access requirements, some database administrators choose to integrate their databases with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the database administrator to off-load those access control functions and focus on core application features and functionality. 

This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are local logon administrator accounts used by system administrators when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "If all user accounts are managed and authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

For accounts managed by Oracle, check DBMS settings to determine if accounts are automatically disabled by the system after 35 days of inactivity. 

In Oracle 12c, Oracle introduced a new security parameter in the profile called INACTIVE_ACCOUNT_TIME. The INACTIVE_ACCOUNT_TIME parameter specifies the number of days permitted the account will be in OPEN state since the last login, after that will be LOCKED if no successful logins happens after the specified duration.

Check to see what profile each user is associated with, if any, with this query:

select username, profile from dba_users order by 1,2;

Then check the profile to see what the inactive_account_time is set to in the table dba_profiles; the inactive_account_time is a value stored in the LIMIT column, and identified by the value inactive_account_time in the RESOURCE_NAME column.

SQL>select profile, resource_name, resource_type, limit from dba_profiles where upper(resource_name) = 'INACTIVE_ACCOUNT_TIME';

If the INACTIVE_ACCOUNT_TIME parameter is set to UNLIMITED (default) or it is set to more than 35 days, this is a finding.

If INACTIVE_ACCOUNT_TIME is not a parameter associated with the profile then check for a script or an automated job that is run daily that checks the audit trail or other means to make sure every user account has logged in within the last 35 days.  If one is not present, this is a finding."
  desc 'fix', "For accounts managed by Oracle, issue the statement:

ALTER PROFILE profile_name  LIMIT inactive_account_time 35;

Or

Change the profile for the DBMS account to ORA_STIG_PROFILE (which has the inactive_account_time parameter set to 35):

ALTER USER user_name PROFILE ora_stig_profile;

An alternate method is to create a script or store procedure that runs once a day.

Write a SQL statement to determine accounts that have not logged in within 35 days:
 
Example:
select username from dba_audit_trail where  action_name = 'LOGON'
group  by username having max(timestamp) < sysdate - 36

And then disable all accounts that have not logged in within 35 days."
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40944r708386_chk'
  tag severity: 'medium'
  tag gid: 'V-237725'
  tag rid: 'SV-237725r879887_rule'
  tag stig_id: 'O121-C2-013800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-40907r667206_fix'
  tag 'documentable'
  tag legacy: ['V-61717', 'SV-76207']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
