control 'SV-233897' do
  title 'The Infoblox system must prohibit or restrict unapproved services, ports, and protocols.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Infoblox systems provide DNS, Dynamic Host Configuration Protocol (DHCP), and IP Address Management (DDI) services. Some of the functions and services provided may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., DNS and DHCP); however, doing so increases risk over limiting the services provided by any one component. This risk may be increased depending on placement in the network. Internal systems often provide DNS and DHCP; however, external systems or those in a DMZ provide only DNS.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.

By default, all services other than those required for management are disabled.  Validate that no additional services have been enabled for DNS members.

1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the "Services" tab and review each service and member status at the top of the panel.

Depending on purchased options, Infoblox DNS members may be running DNS and optionally running services supporting DNS and security operations such as DNS Traffic Control, Threat Protection, Threat Analytics, and TAXII services. 

Use of these additional Infoblox services is not a finding.

If any unnecessary services such as file distribution services are enabled on the DNS members, this is a finding.

Note: Once DNSSEC is enabled, the DNS service will be required to be running on the Grid Master, and it will be placed into stealth mode.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the "Services" tab. 
3. Select each available service at the top of the panel and review the service status. 
4. Click on the member and disable unnecessary services.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37082r611211_chk'
  tag severity: 'medium'
  tag gid: 'V-233897'
  tag rid: 'SV-233897r621666_rule'
  tag stig_id: 'IDNS-8X-400039'
  tag gtitle: 'SRG-APP-000142-DNS-000014'
  tag fix_id: 'F-37047r611212_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
