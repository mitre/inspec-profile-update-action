control 'SV-235027' do
  title 'The SUSE operating system must not have network interfaces in promiscuous mode unless approved and documented.'
  desc 'Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow then to collect information such as logon IDs, passwords, and key exchanges between systems.

If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the Information System Security Officer (ISSO) and restricted to only authorized personnel.'
  desc 'check', 'Verify the SUSE operating system network interfaces are not in promiscuous mode unless approved by the ISSO and documented.

Check for the status with the following command:

> ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system network interfaces to turn off promiscuous mode unless approved by the ISSO and documented.

Set the promiscuous mode of an interface to off with the following command:

> sudo ip link set dev <devicename> promisc off'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38215r619350_chk'
  tag severity: 'medium'
  tag gid: 'V-235027'
  tag rid: 'SV-235027r622137_rule'
  tag stig_id: 'SLES-15-040390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38178r619351_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
