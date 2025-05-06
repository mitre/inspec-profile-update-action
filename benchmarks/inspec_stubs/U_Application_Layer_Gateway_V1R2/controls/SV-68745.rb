control 'SV-68745' do
  title 'The ALG must not have unnecessary services and functions enabled.'
  desc 'Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the ALG. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The primary function of an ALG is to provide application specific content filtering and/or proxy services. The ALG application suite may integrate related content filtering and analysis services and tools (e.g., IPS, proxy, malware inspection, black/white lists). Some gateways may also include email scanning, decryption, caching, and DLP services. However, services and capabilities which are unrelated to this primary functionality must not be installed (e.g., DNS, email client or server, FTP server, or web server).

Next Generation ALGs (NGFW) and Unified Threat Management (UTM) ALGs integrate functions which have been traditionally separated. These products integrate content filtering features to provide more granular policy filtering. There may be operational drawbacks to combining these services into one device. Another issue is that NGFW and UTM products vary greatly with no current definitive industry standard.'
  desc 'check', 'Review the ALG configuration to determine if services or functions not required for operation, or not related to ALG functionality (e.g., DNS, email client or server, FTP server, or web server) are enabled.

If unnecessary services and functions are enabled on the ALG, this is a finding.'
  desc 'fix', 'Remove unneeded services and functions from the ALG. Removal is recommended since the service or function may be inadvertently enabled. However, if removal is not possible, disable the service or function.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55115r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54499'
  tag rid: 'SV-68745r1_rule'
  tag stig_id: 'SRG-NET-000131-ALG-000085'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-59353r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
