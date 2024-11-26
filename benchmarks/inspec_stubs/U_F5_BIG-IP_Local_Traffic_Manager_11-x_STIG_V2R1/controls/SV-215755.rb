control 'SV-215755' do
  title 'The BIG-IP Core implementation must be configured so that only functions, ports, protocols, and/or services that are documented for the server/application for which the virtual servers are providing connectivity.'
  desc 'Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the ALG. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The primary function of an ALG is to provide application-specific content filtering and/or proxy services. The ALG application suite may integrate related content filtering and analysis services and tools (e.g., IPS, proxy, malware inspection, black/white lists). Some gateways may also include email scanning, decryption, caching, and DLP services. However, services and capabilities which are unrelated to this primary functionality must not be installed (e.g., DNS, email client or server, FTP server, or web server).

Next Generation ALGs (NGFW) and Unified Threat Management (UTM) ALGs integrate functions which have been traditionally separated. These products integrate content filtering features to provide more granular policy filtering. There may be operational drawbacks to combining these services into one device. Another issue is that NGFW and UTM products vary greatly with no current definitive industry standard.'
  desc 'check', 'Review the BIG-IP Core configuration to determine if functions, ports, protocols, and/or services not required for operation, or not related to BIG-IP Core functionality (e.g., DNS, email client or server, FTP server, or web server) are enabled.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Review the Virtual Service List and validate all ports listed in the "Service Port" column are documented for each virtual server and are required for operation.

If unnecessary services and functions are enabled on the BIG-IP Core, this is a finding.

If the BIG-IP Core implementation is configured  with functions, ports, protocols, and/or services that are not documented for the server/application for which the virtual servers are providing connectivity, this is a finding.'
  desc 'fix', 'Configure Virtual Servers in the BIG-IP LTM module with only functions, ports, protocols, and/or services that are documented for the servers/applications for which the BIG-IP Core implementation is providing connectivity.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16947r291078_chk'
  tag severity: 'medium'
  tag gid: 'V-215755'
  tag rid: 'SV-215755r557356_rule'
  tag stig_id: 'F5BI-LT-000067'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-16945r291079_fix'
  tag 'documentable'
  tag legacy: ['V-60291', 'SV-74721']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
