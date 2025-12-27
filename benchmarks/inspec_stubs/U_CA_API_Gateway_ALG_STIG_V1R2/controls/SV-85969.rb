control 'SV-85969' do
  title 'The CA API Gateway must be configured to remove or disable unrelated or unneeded application proxy services.'
  desc "Unrelated or unneeded proxy services increase the attack vector and add excessive complexity to the securing of the ALG. Multiple application proxies can be installed on many ALGs. However, proxy types must be limited to related functions. At a minimum, the web and email gateway represent different security domains/trust levels. Organizations should also consider separation of gateways that service the DMZ and the trusted network.

The CA API Gateway allows administrators to register only the necessary services that require reverse proxy to the internal organization’s network. All other services must not be enabled on the CA API Gateway until registered and assigned the appropriate amount of security policy to meet the organization's requirements."
  desc 'check', 'Open the CA API Gateway - Policy Manager and verify the Registered Services installed on the Gateway are only the Registered Services required by the Gateway to manage proxy services in accordance with organizational requirements. 

If there are other services not required by the organization or that the organization is not responsible for managing, this is a finding.'
  desc 'fix', "Open the CA API Gateway - Policy Manager and delete all unrelated or not needed Registered Services that are not required by the organization's CA API Gateway to manage proxy services."
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71345'
  tag rid: 'SV-85969r1_rule'
  tag stig_id: 'CAGW-GW-000280'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-77655r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
