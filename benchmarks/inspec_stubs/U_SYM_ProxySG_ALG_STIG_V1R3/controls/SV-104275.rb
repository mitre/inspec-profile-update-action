control 'SV-104275' do
  title 'Symantec ProxySG must block outbound traffic containing known and unknown denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

Installation of an ALG at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

The ALG must include protection against DoS attacks that originate from inside the enclave that can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.

The appliance can reduce the effects of DoS and distributed-DoS (DDoS) attacks. DoS and DDoS attacks occur when one or more machines coordinate an attack on a specific website to cripple or disrupt host services. As the attack progresses, the target host shows decreased responsiveness and often stops responding. Legitimate HTTP traffic is unable to proceed because the infected system no longer has the resources to process new requests.

ProxySG appliances prevent attacks by limiting the number of simultaneous TCP connections and/or excessive repeated requests from each client IP address that can be established within a specified time frame. If these limits are met, the appliance either does not respond to connection attempts from a client already at this limit or resets the connection. It can also be configured to limit the number of active connections to prevent server overloading.

If the appliance starts seeing a large number of failed requests, and that number exceeds the configured error limit, subsequent requests are blocked and the proxy returns a warning page.

Failed requests, by default, include various HTTP response failures such as 4xx client errors (excluding 401 and 407) and 5xx server errors. The HTTP responses that should be treated as failures can be defined by creating policy.

If the requests continue despite the warnings, and the rate exceeds the warning limits that have been specified for the client, the client is then blocked at the TCP level.'
  desc 'check', 'Verify that Attack Detection is enabled.

1. SSH into the ProxySG console and type "enable".
2. Enter the correct password and type "configure terminal".
3. Press "Enter" and type "show attack-detection configuration". 
4. Verify that "client limits enabled" equals "true".

If Symantec ProxySG does not block outbound traffic containing known and unknown DoS attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints, this is a finding.'
  desc 'fix', 'Enable the Attack Detection function. 

1. SSH into the ProxySG console and type "enable".
2. Enter the correct password and type "configure terminal". 
3. Press "Enter" and type "attack-detection".
4. Type "client" and press "Enter". Type "enable-limits" and press "Enter".

Note: See the ProxySG Administration Guide, Chapter 73: Preventing Denial of Service Attacks, to understand the functionality before proceeding. Fine-tune the default client limits if there is an operational impact.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93507r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94321'
  tag rid: 'SV-104275r1_rule'
  tag stig_id: 'SYMP-AG-000540'
  tag gtitle: 'SRG-NET-000192-ALG-000121'
  tag fix_id: 'F-100437r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
