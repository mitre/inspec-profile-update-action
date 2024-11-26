control 'SV-233273' do
  title 'Container platform components must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Container platform components are part of the overall container platform, offering services that enable the container platform to fully orchestrate user containers. These components may fall outside the scope of this document, but they still must be secured. Examples of such components are DNS, routers, and firewalls. These and any other services offered by the container platform must follow the appropriate STIG or SRG for the technology offered. If a STIG or SRG is not available for the technology, then best practices for the technology must be used. For example, the Cloud Native Computing Foundation (CNCF) is an open-source organization that is working on container platform best practices.'
  desc 'check', 'Review the container platform configuration to determine the services offered by the container platform and validate that any services that are offered are configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and DTMs. 

If container platform services are not configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and DTMs, this is a finding.'
  desc 'fix', 'Configure container services in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36209r601851_chk'
  tag severity: 'medium'
  tag gid: 'V-233273'
  tag rid: 'SV-233273r601852_rule'
  tag stig_id: 'SRG-APP-000516-CTR-001325'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36177r601307_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
