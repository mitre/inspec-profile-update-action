control 'SV-233877' do
  title 'The Infoblox system must be configured to respond to DNS traffic only.'
  desc "OS configuration practices as issued by the US Computer Emergency Response Team (US CERT) and the National Institute of Standards and Technology's (NIST's) National Vulnerability Database (NVD), based on identified vulnerabilities that pertain to the application profile into which the name server software fits, should always be followed. 

In particular, hosts that run the name server software should not provide any other services and therefore should be configured to respond to DNS traffic only. In other words, the only allowed incoming ports/protocols to these hosts should be 53/udp and 53/tcp. 

Outgoing DNS messages should be sent from a random port to minimize the risk of an attacker's guessing the outgoing message port and sending forged replies."
  desc 'check', 'By default, all services other than those required for management are disabled on Infoblox appliances. Review the Infoblox Grid for extra services turned on.

Note: Configuration of out-of-band (OOB) management can be enabled to separate DNS from management traffic if desired.  

1. Navigate to Grid >> Grid Manager >> Services tab. 
2. Click on each service that is running and review the Service Status of each member.  

Note: Depending on purchased options, Infoblox DNS members may be running DNS, and optionally services supporting DNS and security operations such as DNS Traffic Control, Threat Protection, Threat Analytics, and TAXII services. Use of these additional Infoblox services is not a finding.  

If an external authoritative server is running any unnecessary services such as file distribution services, this is a finding.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Services tab. 
2. Click on each service that is running and review the Service Status of each member.  
3. Click on the member and select "Stop" to disable the unnecessary service.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37062r611151_chk'
  tag severity: 'medium'
  tag gid: 'V-233877'
  tag rid: 'SV-233877r621666_rule'
  tag stig_id: 'IDNS-8X-400019'
  tag gtitle: 'SRG-APP-000516-DNS-000109'
  tag fix_id: 'F-37027r611152_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
