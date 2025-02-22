control 'SV-221882' do
  title 'Network interfaces configured on The Oracle Linux operating system must not be in promiscuous mode.'
  desc 'Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow them to collect information such as logon IDs, passwords, and key exchanges between systems.

If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the Information System Security Officer (ISSO) and restricted to authorized personnel only.'
  desc 'check', 'Verify network interfaces are not in promiscuous mode unless approved by the ISSO and documented.

Check for the status with the following command:

# ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding.'
  desc 'fix', 'Configure network interfaces to turn off promiscuous mode unless approved by the ISSO and documented.

Set the promiscuous mode of an interface to off with the following command:

#ip link set dev <devicename> multicast off promisc off'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23597r419718_chk'
  tag severity: 'medium'
  tag gid: 'V-221882'
  tag rid: 'SV-221882r603260_rule'
  tag stig_id: 'OL07-00-040670'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23586r419719_fix'
  tag 'documentable'
  tag legacy: ['V-99503', 'SV-108607']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
