control 'SV-251750' do
  title 'Unicast Reverse Path Forwarding (uRPF) must be enabled on the NSX-T Tier-0 Gateway.'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyber attacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. Distributed denial-of-service (DDoS) attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged.

This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet; thereby mitigating IP source address spoofing.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

For every Tier-0 Gateway, expand Tier-0 Gateway >> Interfaces, and then click on the number of interfaces present to open the interfaces dialog.

Expand each interface to view the URPF Mode configuration.

If URPF Mode is not set to "Strict" on any interface, this is a finding.'
  desc 'fix', 'Enable strict URPF mode on interfaces by doing the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways and expand the target Tier-0 gateway.

Expand Interfaces, then click on the number of interfaces present to open the interfaces dialog. Select "Edit" on the target interface.

From the drop-down, set the URPF mode to "Strict" and then click "Save".'
  impact 0.7
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55187r810132_chk'
  tag severity: 'high'
  tag gid: 'V-251750'
  tag rid: 'SV-251750r810134_rule'
  tag stig_id: 'T0RT-3X-000051'
  tag gtitle: 'SRG-NET-000205-RTR-000014'
  tag fix_id: 'F-55141r810133_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
