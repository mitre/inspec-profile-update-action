control 'SV-224204' do
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
  desc 'check', "Determine all situations where a user must re-authenticate. Check if the mechanisms that handle such situations use the following SQL:

To make a single user re-authenticate, the following must be present:

 SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user='<username>'

To make all users re-authenticate, run the following:

 SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%'

If the provided SQL does not force re-authentication, this is a finding."
  desc 'fix', "Determine the organization-defined circumstances or situations that require re-authentication and ensure the following SQL is executed in those situations.

To require a single user to re-authenticate, use this SQL: 

 SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user = '<username>';

To require all users to re-authenticate, use this SQL: 

 SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%';"
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25877r495630_chk'
  tag severity: 'medium'
  tag gid: 'V-224204'
  tag rid: 'SV-224204r508023_rule'
  tag stig_id: 'EP11-00-008800'
  tag gtitle: 'SRG-APP-000389-DB-000372'
  tag fix_id: 'F-25865r495631_fix'
  tag 'documentable'
  tag legacy: ['SV-109533', 'V-100429']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
