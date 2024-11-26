control 'SV-215739' do
  title 'The BIG-IP Core implementation must be configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, devices) within information systems. Examples of information flow control restrictions include keeping export-controlled information from being transmitted in the clear to the Internet or blocking information marked as classified but being transported to an unapproved destination.

ALGs enforce approved authorizations by employing security policy and/or rules that restrict information system services, provide packet-filtering capability based on header or protocol information, and/or message filtering capability based on data content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'If the BIG-IP Core does not perform packet-filtering intermediary services for virtual servers, this is not applicable.

When packet-filtering intermediary services are performed, verify the BIG-IP Core is configured as follows:

Verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an AFM policy to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Network Firewall" Enforcement is set to "Policy Rules..." and "Policy" is set to use an AFM policy to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

If the BIG-IP Core is not configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic, this is a finding.'
  desc 'fix', 'If user packet-filtering intermediary services are provided, configure the BIG-IP Core as follows: 

Configure a policy in the BIG-IP Advanced Firewall Manager (AFM) module to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of source, destination, headers, and/or content of the communications traffic.

Apply the AFM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to enforce approved authorizations for controlling the flow of information within the network.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16931r291030_chk'
  tag severity: 'medium'
  tag gid: 'V-215739'
  tag rid: 'SV-215739r557356_rule'
  tag stig_id: 'F5BI-LT-000005'
  tag gtitle: 'SRG-NET-000018-ALG-000017'
  tag fix_id: 'F-16929r291031_fix'
  tag 'documentable'
  tag legacy: ['SV-74689', 'V-60259']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
