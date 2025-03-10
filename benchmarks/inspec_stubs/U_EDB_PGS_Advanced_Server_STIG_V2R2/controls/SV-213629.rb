control 'SV-213629' do
  title 'The EDB Postgres Advanced Server must require users to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  desc 'The DoD standard for authentication of an interactive user is the presentation of a Common Access Card (CAC) or other physical token bearing a valid, current, DoD-issued Public Key Infrastructure (PKI) certificate, coupled with a Personal Identification Number (PIN) to be entered by the user at the beginning of each session and whenever re-authentication is required.

Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user re-authenticate.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) When the execution of privileged functions occurs; 
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring re-authentication are privilege escalation and role changes.'
  desc 'check', 'If organization-defined circumstances or situations require re-authentication, and these situations are not configured to terminate existing logins to require re-authentication, this is a finding.'
  desc 'fix', %q(Determine the organization-defined circumstances or situations that require re-authentication and ensure that the following SQL is executed in those situations.  To require a single user to re-authenticate, use this SQL:  "select pg_terminate_backend(pid) from pg_stat_activity where user='<username>';"  To require all users to re-authenticate, use this SQL:  "select pg_terminate_backend(pid) from pg_stat_activity where user like '%';".)
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14851r290199_chk'
  tag severity: 'medium'
  tag gid: 'V-213629'
  tag rid: 'SV-213629r508024_rule'
  tag stig_id: 'PPS9-00-008800'
  tag gtitle: 'SRG-APP-000389-DB-000372'
  tag fix_id: 'F-14849r290200_fix'
  tag 'documentable'
  tag legacy: ['SV-83615', 'V-69011']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
