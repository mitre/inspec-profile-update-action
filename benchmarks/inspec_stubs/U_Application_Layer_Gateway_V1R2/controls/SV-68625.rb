control 'SV-68625' do
  title 'The ALG must restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

This requirement applies to the flow of information between the ALG when used as a gateway or boundary device which allows traffic flow between interconnected networks of differing security policies.

The ALG is installed and configured such that it restricts or blocks information flows based on guidance in the PPSM regarding restrictions for boundary crossing for ports, protocols and services. Information flow restrictions may be implemented based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

The ALG must be configured with policy filters (e.g., security policy, rules, and/or signatures) that restrict or block information system services; provide a packet-filtering capability based on header information; and/or perform message-filtering based on message content. The policy filters used depends upon the type of application gateway (e.g., web, email, or TLS).'
  desc 'check', 'Verify the ALG restricts or blocks harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

If the ALG does not restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic, this is a finding.'
  desc 'fix', 'Configure the ALG to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54995r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54379'
  tag rid: 'SV-68625r1_rule'
  tag stig_id: 'SRG-NET-000019-ALG-000018'
  tag gtitle: 'SRG-NET-000019-ALG-000018'
  tag fix_id: 'F-59233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
