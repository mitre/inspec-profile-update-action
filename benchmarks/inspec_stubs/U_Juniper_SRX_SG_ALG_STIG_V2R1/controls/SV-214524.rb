control 'SV-214524' do
  title 'The Juniper SRX Services Gateway Firewall must not be configured as an NTP server since providing this network service is unrelated to the role as a firewall.'
  desc 'Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the SRX. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The Juniper SRX is a highly configurable platform that can fulfil many roles in the Enterprise or Branch architecture depending on the model installed. Some services are employed for management services; however, these services can often also be provided as a network service on the data plane. Examples of these services are NTP, DNS, and DHCP. Also, as a Next Generation Firewall (NGFW) and Unified Threat Management (UTM) device, the SRX integrate functions which have been traditionally separated. 

The SRX may integrate related content filtering, security services, and analysis services and tools (e.g., IPS, proxy, malware inspection, black/white lists). Depending on licenses purchased, gateways may also include email scanning, decryption, caching, VPN, and DLP services. However, services and capabilities which are unrelated to this primary functionality must not be installed (e.g., DNS, email server, FTP server, or web server).'
  desc 'check', 'Check both the zones and the interface stanza to ensure NTP is not configured as a service option.

[edit]
show security zones

and, for each interface used, enter:

show security zones <zone-name> interface <interface-name>

If NTP is included in any of the zone or interface stanzas, this is a finding.'
  desc 'fix', 'Delete NTP options from zones and interface commands. Re-enter the set security zone command without the "ntp" attribute. The exact command entered depends how the zone is configured with the authorized attributes, services, and options.

Examples: 

[edit]
set security zones security-zone <zone-name> interfaces <interface-name> host-inbound-traffic'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway ALG'
  tag check_id: 'C-15730r297256_chk'
  tag severity: 'medium'
  tag gid: 'V-214524'
  tag rid: 'SV-214524r557389_rule'
  tag stig_id: 'JUSX-AG-000084'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-15728r297257_fix'
  tag 'documentable'
  tag legacy: ['SV-80803', 'V-66313']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
