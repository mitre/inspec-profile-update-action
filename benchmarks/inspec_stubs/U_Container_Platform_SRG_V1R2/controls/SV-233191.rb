control 'SV-233191' do
  title 'The container platform must prevent component execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.'
  desc "The container platform may offer components such as DNS services, firewall services, router services, or web services that are not required by every organization to meet their needs. Container platform components may also add capabilities that run counter to the mission or that provide users with functionality that exceeds mission requirements. To meet the requirements of an organization, the container platform must have a method to remove or disable components not required to meet the organization's mission."
  desc 'check', "Review documentation and configuration setting to determine if policies, rules, or restrictions exist regarding usage of container platform components. 

If no such no restrictions are in place, this is not a finding. 

Identify any components the organization requires to be disabled or removed and configure the container platform according to that policy. 

If the container platform components are not disabled or removed according to the organization's policy, this is a finding."
  desc 'fix', "Configure the container platform so that any platform components that are not required in order to meet the organization's mission are disabled or removed. Document the components that must be disabled or removed for reference."
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36127r601795_chk'
  tag severity: 'medium'
  tag gid: 'V-233191'
  tag rid: 'SV-233191r601796_rule'
  tag stig_id: 'SRG-APP-000384-CTR-000915'
  tag gtitle: 'SRG-APP-000384'
  tag fix_id: 'F-36095r601061_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
