control 'SV-222520' do
  title 'The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user reauthenticate.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change;
(ii) When roles change;
(iii) When security categories of information systems change;
(iv) When the execution of privileged functions occurs;
(v) After a fixed period of time;
or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.'
  desc 'check', 'Review the application guidance and interview the application administrator.

Identify the application user roles.

Identify the methods and manner in which an application user is allowed to escalate their privileges or change their role.

Create or utilize an account that has 2 roles within the application, both should be non-administrator.
Example: User role and Report Creator role.

Authenticate to the application as the user in the User role.

Access the application functionality that allows the user to change their role and change from the User role to the Report Creator role.

If the user is not prompted to reauthenticate before the user’s role is changed, this is a finding.

Log out of the application and log back in as the User role.

Access the application functionality that allows the user to escalate their privileges to an administrative user.

Attempt to escalate the privileges of the user.

If the user is not prompted to reauthenticate before the user is allowed to proceed with escalated privileges, this is a finding.'
  desc 'fix', 'Configure the application to require reauthentication before user privilege is escalated and user roles are changed.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24190r493468_chk'
  tag severity: 'medium'
  tag gid: 'V-222520'
  tag rid: 'SV-222520r879762_rule'
  tag stig_id: 'APSC-DV-001520'
  tag gtitle: 'SRG-APP-000389'
  tag fix_id: 'F-24179r493469_fix'
  tag 'documentable'
  tag legacy: ['SV-84145', 'V-69523']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
