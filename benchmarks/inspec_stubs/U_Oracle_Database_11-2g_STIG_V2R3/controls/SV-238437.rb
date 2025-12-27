control 'SV-238437' do
  title 'The DBMS must provide a mechanism to automatically terminate accounts designated as temporary or emergency accounts after an organization-defined time period.'
  desc 'Temporary application accounts could ostensibly be used in the event of a vendor support visit where a support representative requires a temporary unique account in order to perform diagnostic testing or conduct some other support related activity. When these types of accounts are created, there is a risk that the temporary account may remain in place and active after the support representative has left.  

To address this, in the event temporary application accounts are required, the application must ensure accounts designated as temporary in nature shall automatically terminate these accounts after an organization-defined time period. Such a process and capability greatly reduces the risk that accounts will be misused, hijacked, or data compromised. 

User authentication and account management should be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP.  This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.

Temporary database accounts must be automatically terminated after an organization-defined time period in order to mitigate the risk of the account being used beyond its original purpose or timeframe.'
  desc 'check', "If the organization has a policy, consistently enforced, forbidding the creation of emergency or temporary accounts, this is not a finding.

If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

Check DBMS settings, OS settings, and/or enterprise-level authentication/access mechanisms settings to determine if the site utilizes a mechanism whereby temporary or emergency accounts can be terminated after an organization-defined time period. If not, this is a finding.

Check the profiles to see what the password_life_time is set to in the table dba_profiles. The password_life_time is a value stored in the LIMIT column, and identified by the value PASSWORD_LIFE_TIME in the RESOURCE_NAME column.

SQL>select
profile,
resource_name,
resource_type,
limit
from dba_profiles
where upper(resource_name) like 'PASSWORD_LIFE_TIME';

Verify that the user in question is assigned to a profile with the PASSWORD_LIFE_TIME set to the amount of time the user is expected to be using the password.  If not, this is a finding."
  desc 'fix', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, no fix to the DBMS is required.

If using database mechanisms to satisfy this requirement, use a profile with a distinctive name (for example, TEMPORARY_USERS), so that temporary users can be easily identified.  Whenever a temporary user account is created, assign it to this profile.

Create a job to lock accounts under this profile that are more than n days old, where n is the organization-defined time period.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41648r667483_chk'
  tag severity: 'medium'
  tag gid: 'V-238437'
  tag rid: 'SV-238437r667485_rule'
  tag stig_id: 'O112-C2-002000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41607r667484_fix'
  tag 'documentable'
  tag legacy: ['V-52353', 'SV-66569']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
