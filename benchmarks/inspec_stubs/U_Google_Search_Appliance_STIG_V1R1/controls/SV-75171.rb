control 'SV-75171' do
  title 'Google Search Appliance users must utilize a separate, distinct administrative account when accessing application security functions or security-relevant information. Non-privileged accounts must be utilized when accessing non-administrative application functions. The application must provide this functionality itself or leverage an existing technology providing this capability.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy such as Role Based Access Control (RBAC) is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account. 

Audit of privileged activity may require physical separation employing information systems on which the user does not have privileged access.

To limit exposure and provide forensic history of activity when operating from within a privileged account or role, the application must support organizational requirements that users of information system accounts, or roles, with access to organization-defined list of security functions or security-relevant information, use non-privileged accounts, or roles, when accessing other (non-security) system functions.

If feasible, applications should provide access logging that ensures users who are granted a privileged role (or roles) have their privileged activity logged.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Log on to the GSA Admin Console.

Select "Administration".

Select "User Accounts".

If there are appropriate "manager" and "admin" accounts per site specific organizational requirement guidance, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Log on to the GSA Admin Console.

Select "Administration".

Select "User Accounts".

Create the appropriate "manager" and "admin" accounts per site specific organizational requirement guidance.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61665r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60719'
  tag rid: 'SV-75171r1_rule'
  tag stig_id: 'GSAP-00-000135'
  tag gtitle: 'SRG-APP-000063'
  tag fix_id: 'F-66399r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000040']
  tag nist: ['AC-6 (2)']
end
