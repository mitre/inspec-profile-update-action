control 'SV-85961' do
  title 'The CA API Gateway must protect audit information from unauthorized read access.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or simply identify an improperly configured network element. Thus, it is imperative that the collected log data from the various network elements, as well as the auditing tools, be secured and can only be accessed by authorized personnel.

Audited events are protected by default by only allowing access to the audited events to authorized users of the CA API Gateway - Policy Manager. Any user requiring access to the audit Information must be explicitly granted access to the Policy Manager auditing tool as per organizational requirements.'
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Select "Tasks" from the main menu and chose "Manage Roles". Verify that only authorized users have been given the "View Audit Records" role. 

If unauthorized users are granted this role, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager as an administrator. 

Select "Tasks" from the main menu and chose "Manage Roles".

Remove the unauthorized user from any role they should not be a member of, including the "View Audit Records" role. 

Additionally, consider removing the user completely or removing the user from any groups within the identity provider that may be assigned to a role for which the user may not be authorized.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71737r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71337'
  tag rid: 'SV-85961r1_rule'
  tag stig_id: 'CAGW-GW-000240'
  tag gtitle: 'SRG-NET-000098-ALG-000056'
  tag fix_id: 'F-77647r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
