control 'SV-214696' do
  title 'The Juniper SRX Services Gateway VPN must use anti-replay mechanisms for security associations.'
  desc 'Anti-replay is an IPsec security mechanism at a packet level which helps to avoid unwanted users from intercepting and modifying an ESP packet.

The SRX adds a sequence number to the ESP encapsulation which is verified by the VPN peer so packets are received within a correct sequence. This will cause issues if packets are not received in the order in which they were sent out.

By default the SRX has a replay window of 64 or 32, depending on the platform. The SRX drops packets received out of order that are not received within this window. However, this default may be overridden by setting the option no-anti-replay as follows: set security vpn name ike no-anti-replay.'
  desc 'check', 'Verify anti-replay service is enabled.

[edit]
show security ipsec security-associations index 16384 detail

If anti-replay service is not enabled, this is a finding.'
  desc 'fix', 'Remove the no-anti-replay Internet Key Exchange (IKE) option from the VPN configuration. By default the SRX has a replay window of 64 or 32, depending on the platform. 

Example: 
[edit]
delete security vpn name ike no-anti-replay'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15897r297675_chk'
  tag severity: 'medium'
  tag gid: 'V-214696'
  tag rid: 'SV-214696r856580_rule'
  tag stig_id: 'JUSX-VN-000031'
  tag gtitle: 'SRG-NET-000147'
  tag fix_id: 'F-15895r297676_fix'
  tag 'documentable'
  tag legacy: ['V-66679', 'SV-81169']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
