control 'SV-75269' do
  title 'The Arista Multilayer Switch must enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. 

A few examples of flow control restrictions include: keeping export-controlled information from being transmitted in the clear to the Internet and blocking information marked as classified but which is being transported to an unapproved destination. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, routers, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet filtering capability based on header information, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'Verify the use of Spanning-Tree Protocol for information flow control via the "show spanning-tree" command.

Alternatively, from the output of the "show running-config" command, review the configuration for "spanning-tree mode" statement, and verify the line "spanning-tree disabled" is not present for production VLANs.

If spanning-tree is not used for controlling the flow of information, this is a finding.'
  desc 'fix', 'Configure the switch to use spanning-tree protocol for Layer-2 connections.

The version of spanning-tree protocol as well as the VLANs upon which it is enabled must be determined according to organizational use and site policy.

For full configuration examples, refer to the Arista Configuration Manual, Chapter 20.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series L2S'
  tag check_id: 'C-61735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60813'
  tag rid: 'SV-75269r1_rule'
  tag stig_id: 'AMLS-L2-000100'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-66499r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
