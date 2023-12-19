control 'SV-228862' do
  title 'The Palo Alto Networks security platform must only allow incoming communications from organization-defined authorized sources forwarded to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application-level firewalls and Web content filters), ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.

Security policies on the Palo Alto Networks security platform match source, destination, application and a service. The application and service columns specify what applications can be identified on a defined set of ports, or on all available ports. The service column allows administrator to define one of the following:
Application-default - The service application-default sets security policy to allow the application on the standard ports associated with the application.
Pre-defined service “service-http” and “service-https” - The pre-defined services use TCP ports 80 and 8080 for HTTP, and TCP port 443 for HTTPS. Use this security policy if you want to restrict web browsing and HTTPS to these ports.
Any - Use this service to deny applications.
Custom service - Use this to define TCP/UDP port numbers to restrict applications to specific ports.'
  desc 'check', 'Obtain and review the list of authorized sources and destinations.  This is usually part of the System Design Specification or Accreditation Package.
Go to Policies >> Security; review each of the configured security policies in turn.
If any of the policies allows traffic that is not part of the authorized sources and destinations list, this is a finding.'
  desc 'fix', 'To create or edit a Security Policy,
Go to Policies >> Security
Select "Add" to create a new security policy, or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31097r513881_chk'
  tag severity: 'medium'
  tag gid: 'V-228862'
  tag rid: 'SV-228862r557387_rule'
  tag stig_id: 'PANW-AG-000107'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-31074r513882_fix'
  tag 'documentable'
  tag legacy: ['SV-77095', 'V-62605']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
