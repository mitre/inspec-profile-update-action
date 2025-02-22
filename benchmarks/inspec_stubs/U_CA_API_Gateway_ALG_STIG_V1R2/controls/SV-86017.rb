control 'SV-86017' do
  title 'The CA API Gateway providing intermediary services for remote access communications traffic must control remote access methods.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, that lack automated control capabilities increase risk and makes remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

The CA API Gateway must control access to Remote Services accessible over broadband and wireless connections using customizable policies and communications protocol Assertions.'
  desc 'check', "Open the CA API GW - Policy Manager. 

Verify the Services requiring remote access controls are registered on the Gateway. 

Check each Service's policy and verify the required communications protocols' Assertions have been added as per organizational requirements. 

Additionally, select Tasks >> Manage Listen Ports and verify listen ports have been created for each type of Remote Access, such as HTTP, HTTPS, FTP, etc. 

If the required communication protocols have not been set in the policies or the listen ports have not been configured, this is a finding."
  desc 'fix', 'Open the CA API GW - Policy Manager. 

Select the Registered Services that do not have controls for Access Methods that are responsible for remote access communications traffic, such as FTP, HTTP, HTTPS, etc. 

Using the Message Routing Policy Assertions, customize the security policies for the Services to include the various types of communications protocols, such as FTP, HTTP, HTTPS, etc. Include only the required organizational remote access protocols. 

Additionally, select Tasks >> Manage Listen Ports and create the required listen ports for the remote access methods needed. If policies are required to be attached to the port, as is the case with an FTP Listen port, assign the policy to the listen port in accordance with organizational requirements for managing and monitoring the remote access protocol and communication traffic.

All other communications protocols and methods will be rejected.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71793r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71393'
  tag rid: 'SV-86017r1_rule'
  tag stig_id: 'CAGW-GW-000520'
  tag gtitle: 'SRG-NET-000313-ALG-000010'
  tag fix_id: 'F-77711r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
