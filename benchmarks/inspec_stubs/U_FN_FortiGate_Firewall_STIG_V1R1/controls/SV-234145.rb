control 'SV-234145' do
  title 'The FortiGate firewall must block outbound traffic containing denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of a firewall at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

The firewall must include protection against DoS attacks that originate from inside the enclave that can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Policy and Objects.
2. Go to IPv4 DoS Policy.
3. Verify different DoS policies that include Incoming Interface, Source Address, Destination Address, and Services have been created.
4. Verify the DoS policies are configured to block L3 and L4 anomalies.

If the DoS policies are not configured to block the outbound traffic, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 DoS Policy or IPv6 DoS Policy.
3. Click +Create New.
4. Select the Incoming Interface.
5. Select Source and Destination addresses.
6. Select the Service.
7. Enable desired L3 and L4 anomalies and thresholds.
8. Ensure the Enable this policy is toggled to right.
9. Click OK.
10. Ensure a policy is created for each interface where there is potential risk of DoS.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37330r611433_chk'
  tag severity: 'medium'
  tag gid: 'V-234145'
  tag rid: 'SV-234145r628776_rule'
  tag stig_id: 'FNFG-FW-000070'
  tag gtitle: 'SRG-NET-000192-FW-000029'
  tag fix_id: 'F-37295r611434_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
