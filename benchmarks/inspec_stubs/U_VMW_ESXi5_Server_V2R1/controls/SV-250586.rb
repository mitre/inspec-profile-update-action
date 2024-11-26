control 'SV-250586' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in Denial-of-Service by exhausting the available space on the target file system. The kernel core dump process may increase the amount of time a system is unavailable due to a crash. Kernel core dumps can be useful for kernel debugging.'
  desc 'check', "Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. Open a root console session to the ESXi host. Retrieve the currently active diagnostic partition using the esxcli command line utility. The output (when configured) looks similar to : Active: mpx.vmhba2:C0:T0:L0:7 and Configured: mpx.vmhba2:C0:T0:L0:7.
# esxcli system coredump partition get

Use the device information from the above command to determine partition size (100MB required, 200MB recommended):
# esxcli storage core device partition list 

For ESXi 5.0 servers (standalone or managed by vCenter Server) that have kernel core dumps configured locally:
If the ESXi 5.0 server's local dump partition size is at least 100 MB, this is not a finding.

For ESXi 5.0 servers managed by vCenter Server using the ESXi Network Dump Collector, dump partition size is a function of the number of systems configured to use the remote collection system. The configuration (size) of the dump partition is not applicable for this check.

If the ESXi 5.0 server's dump partition is hosted on a remote device using the ESXi Network Dump Collector, this is not a finding."
  desc 'fix', %q(For ESXi 5.0 servers (standalone or managed by vCenter Server) that have kernel core dumps configured locally:
To create a diagnostic coredump partition on disk, select a storage device with at least 100MB of free space (200MB recommended) that is accessible by the ESXi host. Ensure the storage device you intend to use does not contain any useful data as it will be overwritten. Use the partedUtil command line utility (refer to the vendor's documentation) to create a new partition. Then use the esxcli command line utility to list all accessible diagnostic partitions.
# esxcli system coredump partition list

The output appears similar to:
Name					Path				Active	Configured
----------------------------------		------				---------	----------------
mpx.vmhba2:C0:T0:L0:7	/vmfs/devices/...	false	false

Configure and activate one of the accessible diagnostic partitions using the esxcli command line utility.
# esxcli system coredump partition set --partition="Partition_Name"
# esxcli system coredump partition set --enable true

Validate that the diagnostic partition is now active using the command:
# esxcli system coredump partition list

The output should now appear similar to:
Name					Path				Active	Configured
----------------------------------		------				---------	----------------
mpx.vmhba2:C0:T0:L0:7	/vmfs/devices/...	true		true


For ESXi 5.0 servers managed by vCenter Server using a network core dump server:
View the current network configuration.
# esxcli system coredump network get

Specify the VMkernel network interface to use for outbound traffic and the IP address/UDP port number of the remote network coredump server.
# esxcli system coredump network set --interface-name <VMkernelInterface> --server-ipv4 <IPAddress> --server-port PortNumber

Enable the above selected network coredump configuration.
# esxcli system coredump network set --enable true

Confirm the configuration.
# esxcli system coredump network get)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54021r798755_chk'
  tag severity: 'medium'
  tag gid: 'V-250586'
  tag rid: 'SV-250586r798757_rule'
  tag stig_id: 'GEN003510-ESXI5-006660'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53975r798756_fix'
  tag 'documentable'
  tag legacy: ['SV-51213', 'V-39355']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
