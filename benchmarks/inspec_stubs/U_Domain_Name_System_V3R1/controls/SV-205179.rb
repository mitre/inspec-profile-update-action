control 'SV-205179' do
  title 'The DNS server implementation must enforce approved authorizations for controlling the flow of information between DNS servers and between DNS servers and DNS clients based on DNSSEC policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all application information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Application-specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy.

Within the context of DNS, this is applicable in terms of controlling the flow of DNS information between systems, such as DNS zone transfers.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server enforces approved authorizations for controlling the information flow by using DNSSEC and TSIG signing practices that restrict zone transfers between DNS servers, and dynamic updates from DNS clients to the master name server, to digitally signed traffic.

If the DNS server does not enforce approved authorizations for controlling the information flow by using DNSSEC and TSIG signing practices, restricting zone transfers between DNS servers and dynamic updates from DNS clients to the master name server to digitally signed traffic, this is a finding.'
  desc 'fix', 'Configure the DNS server to enforce approved authorizations for controlling the information flow by applying DNSSEC and TSIG signing practices to the DNS implementation.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5446r392453_chk'
  tag severity: 'medium'
  tag gid: 'V-205179'
  tag rid: 'SV-205179r879635_rule'
  tag stig_id: 'SRG-APP-000215-DNS-000003'
  tag gtitle: 'SRG-APP-000215'
  tag fix_id: 'F-5446r392454_fix'
  tag 'documentable'
  tag legacy: ['SV-69067', 'V-54821']
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
