control 'SV-206517' do
  title 'The Central Log Server must be configured with the organization-defined severity or criticality levels of each event that is being sent from individual devices or hosts.'
  desc 'This supports prioritization functions, which is a major reason why centralized management is a requirement in DoD. This includes different features that help highlight the important events over less critical security events. This may be accomplished by correlating security events with vulnerability data or other asset information. Prioritization algorithms often use severity information provided by the original log source as well. The criticality levels used by the site and the actions that are taken based on the levels established for each system are documented in the SSP. These levels and actions can only be leveraged for alerts, notifications, and reports which correlate asset information if they are configured in the Central Log Server.'
  desc 'check', 'Obtain the site’s SSP to see which criticality levels are used for each system within the scope of the Central Log Server. Examine the configuration of the Central Log Server.

Verify the Central Log Server is configured with the organization-defined severity or criticality levels of each event that is being sent from individual devices or hosts.

If the Central Log Server is not configured with the organization-defined severity or criticality levels of each event that is being sent from individual devices or hosts, this is a finding.'
  desc 'fix', 'Configure the Central Log Server with the organization-defined severity or criticality levels of each event that is being sent from individual devices or hosts.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6777r285792_chk'
  tag severity: 'medium'
  tag gid: 'V-206517'
  tag rid: 'SV-206517r401224_rule'
  tag stig_id: 'SRG-APP-000516-AU-000380'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-6777r285793_fix'
  tag 'documentable'
  tag legacy: ['SV-95903', 'V-81189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
