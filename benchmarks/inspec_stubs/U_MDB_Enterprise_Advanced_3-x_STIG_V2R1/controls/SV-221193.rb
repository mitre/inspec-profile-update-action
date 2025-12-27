control 'SV-221193' do
  title 'MongoDB must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.'
  desc 'The DoD standard for authentication of an interactive user is the presentation of a Common Access Card (CAC) or other physical token bearing a valid, current, DoD-issued Public Key Infrastructure (PKI) certificate, coupled with a Personal Identification Number (PIN) to be entered by the user at the beginning of each session and whenever reauthentication is required.

Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user reauthenticate.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change;
(ii) When roles change;
(iii) When security categories of information systems change;
(iv) When the execution of privileged functions occurs;
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.'
  desc 'check', 'If organization-defined circumstances or situations require reauthentication, and these situations are not configured to terminate existing logins to require reauthentication, this is a finding.'
  desc 'fix', 'Determine the organization-defined circumstances or situations that require reauthentication and ensure that the mongod and mongos processes are stopped/started (restart).'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22908r411073_chk'
  tag severity: 'medium'
  tag gid: 'V-221193'
  tag rid: 'SV-221193r411075_rule'
  tag stig_id: 'MD3X-00-000700'
  tag gtitle: 'SRG-APP-000389-DB-000372'
  tag fix_id: 'F-22897r411074_fix'
  tag 'documentable'
  tag legacy: ['SV-96627', 'V-81913']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
