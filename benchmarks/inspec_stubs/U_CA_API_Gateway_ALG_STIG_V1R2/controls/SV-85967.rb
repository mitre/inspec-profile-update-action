control 'SV-85967' do
  title 'The CA API Gateway must not have unnecessary services and functions enabled.'
  desc 'Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the ALG. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The primary function of an ALG is to provide application-specific content filtering and/or proxy services. The ALG application suite may integrate related content filtering and analysis services and tools (e.g., IPS, proxy, malware inspection, black/white lists). Some gateways may also include email scanning, decryption, caching, and DLP services. However, services and capabilities that are unrelated to this primary functionality must not be installed (e.g., DNS, email client or server, FTP server, or web server).

Next Generation ALGs (NGFW) and Unified Threat Management (UTM) ALGs integrate functions that have traditionally been separated. These products integrate content filtering features to provide more granular policy filtering. There may be operational drawbacks to combining these services into one device. Another issue is that NGFW and UTM products vary greatly, with no current definitive industry standard.

The CA API Gateway must not enable unnecessary services unless required by a Registered Service to be used in accordance with organizational requirements.'
  desc 'check', 'Open the CA API Gateway - Policy Manager, select "Tasks" from the main menu, and chose "Manage Listen Ports". 

If the Listen ports or firewall rules are not configured in accordance with organizational requirements for disabling unnecessary services, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager, select "Tasks" from the main menu, and chose "Manage Listen Ports". 

Update the Listen ports and firewall rules in accordance with organizational requirements for disabling unnecessary services.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71343'
  tag rid: 'SV-85967r1_rule'
  tag stig_id: 'CAGW-GW-000270'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-77653r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
