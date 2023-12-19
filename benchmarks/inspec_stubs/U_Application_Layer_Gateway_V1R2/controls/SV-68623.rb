control 'SV-68623' do
  title 'The ALG must enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, devices) within information systems. Examples of information flow control restrictions include keeping export controlled information from being transmitted in the clear to the Internet or blocking information marked as classified but is being transported to an unapproved destination.

ALGs enforce approved authorizations by employing security policy and/or rules that restrict information system services, provide packet filtering capability based on header or protocol information and/or message filtering capability based on data content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'Verify the ALG is configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

If the ALG is not configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic, this is a finding.'
  desc 'fix', 'Configure the ALG to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54377'
  tag rid: 'SV-68623r1_rule'
  tag stig_id: 'SRG-NET-000018-ALG-000017'
  tag gtitle: 'SRG-NET-000018-ALG-000017'
  tag fix_id: 'F-59231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
