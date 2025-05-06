control 'SV-214163' do
  title 'Infoblox systems configured to run the DNS service must be configured to prohibit or restrict unapproved ports and protocols.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements by providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

By default all services other than those required for management are disabled. Validate that no additional services have been enabled for DNS members.

Navigate to Grid >> Grid Manager >> Services tab and review each service and member status at the top of the panel.

Depending upon purchased options, Infoblox DNS members may be running DNS, Reporting, Threat Protection, Threat Analytics, and TAXII services, this is not a finding. If any unnecessary services such as file distribution services are enabled on the DNS members, this is a finding.

Note: Once DNSSEC is enabled, the DNS service will be required to be running on the Grid Master.'
  desc 'fix', 'Navigate to Grid >> Grid Manager >> Services tab.

Select each available service at the top of the panel and review the Service Status.

Click on the member and disable unnecessary services.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15378r295755_chk'
  tag severity: 'medium'
  tag gid: 'V-214163'
  tag rid: 'SV-214163r612370_rule'
  tag stig_id: 'IDNS-7X-000130'
  tag gtitle: 'SRG-APP-000142-DNS-000014'
  tag fix_id: 'F-15376r295756_fix'
  tag 'documentable'
  tag legacy: ['V-68523', 'SV-83013']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
