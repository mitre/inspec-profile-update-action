control 'SV-223243' do
  title 'SharePoint must enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy.'
  desc 'Information flow control regulates where information is allowed to travel within an information system and between information systems (as opposed to who is allowed to access the information) and without explicit regard to subsequent accesses to that information.

From an application perspective, flow control is established once application data flow modeling has been completed. Data flow modeling can be described as the process of identifying, modeling, and documenting how data moves around an information system. Data flow modeling examines processes (activities that transform data from one form to another), data stores (the holding areas for data), external entities (what sends data into a system or receives data from a system), and data flows (routes by which data can flow).

Once the application data flows have been identified, corresponding flow controls can be applied at the appropriate points.

A few examples of flow control restrictions include the following: keeping export-controlled information from being transmitted in the clear to the Internet and blocking information that is marked as classified but is being transported to an unapproved destination. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, devices) within information systems and between interconnected systems. Flow control is based on the characteristics of the information and/or the information path.

Application-specific examples of flow control enforcement can be found in information protection software (e.g., guards, proxies, gateways, and cross domain solutions) employing rule sets or establishing configuration settings restricting information system services or providing message-filtering capability based on content (e.g., using key word searches or document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy.

SharePoint Central Administrator is a powerful management tool used to administer the farm. This server should be installed on a trusted network segment. This server should be used to run required services rather than user-oriented web applications.'
  desc 'check', 'Review the SharePoint server configuration to ensure approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy are enforced.

Inspect the logical location of the server farm web front end servers on a network diagram.

Verify the Central Administration site is not installed on a server located in a DMZ or other publicly accessible segment of the network.

If Central Administrator is installed on a publicly facing SharePoint server, this is a finding.'
  desc 'fix', 'Configure the SharePoint server to enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy.

Remove the application server from the DMZ.'
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24916r430789_chk'
  tag severity: 'high'
  tag gid: 'V-223243'
  tag rid: 'SV-223243r612235_rule'
  tag stig_id: 'SP13-00-000030'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-24904r430790_fix'
  tag 'documentable'
  tag legacy: ['SV-74373', 'V-59943']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
