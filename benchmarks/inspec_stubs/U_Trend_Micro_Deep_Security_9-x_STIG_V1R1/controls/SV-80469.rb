control 'SV-80469' do
  title 'Trend Deep Security must implement organization-defined automated security responses if baseline configurations are changed in an unauthorized manner.'
  desc 'Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the system. Changes to information system configurations can have unintended side effects, some of which may be relevant to security. 

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the application. Examples of security responses include, but are not limited to the following: halting application processing; halting selected application functions; or issuing alerts/notifications to organizational personnel when there is an unauthorized modification of a configuration item.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure organization-defined automated security responses are implemented if baseline configurations are changed in an unauthorized manner.

Deep Security, Policies, are policy templates that specify the security rules to be configured and enforced automatically for one or more computers. These compact, manageable rule sets make it simple to provide comprehensive security without the need to manage thousands of rules. Default Policies provide the necessary rules for a wide range of common computer configurations. 

1. Analyze the system using the Administration >> System Settings >> Alerts tab. Review the email address listed in the “Alert Event Forwarding (From The Manager).” 

If this email address is not present or does not belong to a distribution for system administrator and ISSOs, this is a finding.

2. Analyze the system using the Administration >> System Settings >> System Events tab to ensure the following events are enabled:

 350 Policy Created  Record Forward
 351 Policy Deleted  Record Forward
 352 Policy Updated  Record Forward
 353 Policies Exported Record Forward
 354 Policies Imported Record Forward

If the options for “Record” and “Forward” are not enabled on these events, this is a finding'
  desc 'fix', 'Configure the Trend Deep Security server to implement organization-defined automated security responses if baseline configurations are changed in an unauthorized manner.

Configure the application to prevent unauthorized changes to the baseline policies by selecting Administration >> System Settings >> System Events.

Enable the Record and Forward option for each of the following:
 
 350 Policy Created
 351 Policy Deleted
 352 Policy Updated 
 353 Policies Exported
 354 Policies Imported'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65979'
  tag rid: 'SV-80469r1_rule'
  tag stig_id: 'TMDS-00-000290'
  tag gtitle: 'SRG-APP-000379'
  tag fix_id: 'F-72055r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
