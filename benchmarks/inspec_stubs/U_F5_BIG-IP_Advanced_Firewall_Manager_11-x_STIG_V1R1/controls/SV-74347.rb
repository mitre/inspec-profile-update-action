control 'SV-74347' do
  title 'The BIG-IP AFM module must be configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, devices) within information systems. Examples of information flow control restrictions include keeping export-controlled information from being transmitted in the clear to the Internet or blocking information marked as classified but being transported to an unapproved destination.

Application Layer Gateways (ALGs) enforce approved authorizations by employing security policy and/or rules that restrict information system services, provide packet filtering capability based on header or protocol information and/or message filtering capability based on data content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'If the BIG-IP AFM module is not used to support user access control intermediary services for virtual servers, this is not applicable.

Verify the BIG-IP AFM module is configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

Navigate to the BIG-IP System manager >> Security >> Network Firewall >> Active Rules.

Verify an active rule is configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

If the BIG-IP AFM module is not configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic, this is a finding.'
  desc 'fix', 'If the BIG-IP AFM module is used to support user access control intermediary services for virtual servers, configure the BIG-IP AFM module to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP AFM 11.x'
  tag check_id: 'C-60605r1_chk'
  tag severity: 'medium'
  tag gid: 'V-59917'
  tag rid: 'SV-74347r1_rule'
  tag stig_id: 'F5BI-AF-000005'
  tag gtitle: 'SRG-NET-000018-ALG-000017'
  tag fix_id: 'F-65325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
