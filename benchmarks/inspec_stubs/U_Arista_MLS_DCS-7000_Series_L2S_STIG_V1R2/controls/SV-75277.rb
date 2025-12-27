control 'SV-75277' do
  title 'The Arista Multilayer Switch must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. 

Examples of flow control restrictions include blocking outside traffic claiming to be from within the organization, and not passing any web requests to the Internet not from the internal web proxy. Additional examples of restrictions include: keeping export-controlled information from being transmitted in the clear to the Internet, and blocking information marked as classified, but which is being transported to an unapproved destination. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, routers, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet filtering capability based on header information, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'Verify the use of MAC Access Control Lists to prevent unintended information flow between network segments. 

For network boundary interfaces, verify the use of an access control list by entering "show mac access-list summary" to validate the use of an access control list on the interface. 

Verify the access control list restricts network traffic as intended by entering "show mac access-list [name]" and substituting the name of the access control list for the bracketed variable.

If there is no access control list configured, or if the access control list does not prevent unintended flow of information between network segments, this is a finding.'
  desc 'fix', 'Configure an Access Control List to control information flow between connected networks.
Configuration Example
configure
mac access-list STIG
 permit [src mac] [src mask] [dst mac] [dst mask]/[any] [protocol]
exit'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series L2S'
  tag check_id: 'C-61767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60821'
  tag rid: 'SV-75277r1_rule'
  tag stig_id: 'AMLS-L2-000110'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-66531r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
