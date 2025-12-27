control 'SV-222627' do
  title 'The ISSO must ensure if a DoD STIG or NSA guide is not available, a third-party product will be configured by following available guidance.'
  desc 'Not all COTS products are covered by a STIG. Those products not covered by a STIG, should follow commercially accepted best practices, independent testing results and vendors lock down guides and recommendations if they are available.'
  desc 'check', 'Review the application documentation to identify application name, features and version.

Identify if a DoD STIG or NSA guide is available.

If no STIG is available for the product, the application and application components must be configured by the following as available: 

- commercially accepted practices, 
- independent testing results, or 
- vendor literature and lock down guides.

If the application and application components do not have DoD STIG or NSA guidance available and are not configured according to: 
commercially accepted practices, 
independent testing results,
or vendor literature and lock down guides, this is a finding.'
  desc 'fix', 'Configure the application according to the product STIG or when a STIG is not available, utilize:

- commercially accepted practices,
- independent testing results, or
- vendor literature and lock down guides.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24297r493789_chk'
  tag severity: 'medium'
  tag gid: 'V-222627'
  tag rid: 'SV-222627r879887_rule'
  tag stig_id: 'APSC-DV-002970'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24286r493790_fix'
  tag 'documentable'
  tag legacy: ['SV-84933', 'V-70311']
  tag cci: ['CCI-000363']
  tag nist: ['CM-6 a']
end
