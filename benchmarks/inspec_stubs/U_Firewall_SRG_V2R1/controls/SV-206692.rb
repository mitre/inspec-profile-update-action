control 'SV-206692' do
  title 'The firewall must block outbound traffic containing denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of a firewall at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

The firewall must include protection against DoS attacks that originate from inside the enclave that can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.'
  desc 'check', 'Obtain and review the list of outbound interfaces and zones from site personnel.

Review each of the configured outbound interfaces and zones. Verify zones that communicate outbound have been configured with the DoS firewall filter (i.e., rules, access control lists [ACLs], screens, or policies) such as IP sweeps, TCP sweeps, buffer overflows, unauthorized port scanning, SYN floods, UDP floods, and UDP sweeps.

If all outbound interfaces are not configured to block DoS attacks, this is a finding.'
  desc 'fix', 'Associate a properly configured DoS firewall filter (e.g., rules, access control lists [ACLs], screens, or policies) to outbound interfaces and security zones.

Apply a firewall filter to each outbound interface example:

set security zones security-zone untrust interfaces <OUTBOUND-INTERFACE>
set security zones security-zone trust screen untrust-screen'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6949r297855_chk'
  tag severity: 'medium'
  tag gid: 'V-206692'
  tag rid: 'SV-206692r604133_rule'
  tag stig_id: 'SRG-NET-000192-FW-000029'
  tag gtitle: 'SRG-NET-000192'
  tag fix_id: 'F-6949r297856_fix'
  tag 'documentable'
  tag legacy: ['SV-94125', 'V-79419']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
