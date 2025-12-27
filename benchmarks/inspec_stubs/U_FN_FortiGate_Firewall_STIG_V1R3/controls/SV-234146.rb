control 'SV-234146' do
  title 'The FortiGate firewall implementation must manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks.'
  desc %q(A firewall experiencing a DoS attack will not be able to handle production traffic load. The high utilization and CPU caused by a DoS attack will also have an effect on control keep-alives and timers used for neighbor peering resulting in route flapping and will eventually black hole production traffic.

The device must be configured to contain and limit a DoS attack's effect on the device's resource utilization. The use of redundant components and load balancing are examples of mitigating "flood-type" DoS attacks through increased capacity.)
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Policy and Objects.
2. Go to IPv4 DoS Policy.
3. Verify different DoS policies that include Incoming Interface, Source Address, Destination Address, and Services have been created.
4. Verify the DoS policies are configured to block L3 and L4 anomalies.

If the DoS policies are not configured to block excess traffic, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 DoS Policy or IPv6 DoS Policy.
3. Click +Create New.
4. Select the Incoming Interface.
5. Select Source and Destination addresses.
6. Select the Service.
7. Enable desired L3 and L4 anomalies and thresholds.
8. Ensure the Enable this policy is toggle to right.
9. Click OK.
10. Ensure a policy is created for each interface where there is potential risk of DoS.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37331r611436_chk'
  tag severity: 'medium'
  tag gid: 'V-234146'
  tag rid: 'SV-234146r611438_rule'
  tag stig_id: 'FNFG-FW-000075'
  tag gtitle: 'SRG-NET-000193-FW-000030'
  tag fix_id: 'F-37296r611437_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
