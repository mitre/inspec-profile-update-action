control 'SV-24663' do
  title 'Each database user, application or process should have an individually assigned account.'
  desc 'Use of accounts shared by multiple users, applications, or processes limit the accountability for actions taken in or on the data or database. Individual accounts provide an opportunity to limit database authorizations to those required for the job function assigned to each individual account.'
  desc 'check', 'Review DBMS account names against the list of authorized DBMS accounts in the System Security Plan.

If any accounts indicate use by mulitiple persons that are not mapped to a specific person, this is a Finding.

If any applications or processes share an account that could be assigned an individual account or are not specified as requiring a shared account, this is a Finding.

Note: Privileged installation accounts may be required to be accessed by DBA or other administrators for system maintenance. In these cases, each use of the account must be logged in some manner to assign accountability for any actions taken during the use of the account.'
  desc 'fix', 'Create individual accounts for each user, application, or other process that requires a database connection.

Document any accounts that are shared where separation is not supported by the application or for maintenance support.

Design, develop and implement a method to log use of any account to which more than one person has access.

Restrict interactive access to shared accounts to the fewest persons possible.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1068r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15613'
  tag rid: 'SV-24663r1_rule'
  tag stig_id: 'DG0078-ORACLE11'
  tag gtitle: 'DBMS individual accounts'
  tag fix_id: 'F-2541r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
