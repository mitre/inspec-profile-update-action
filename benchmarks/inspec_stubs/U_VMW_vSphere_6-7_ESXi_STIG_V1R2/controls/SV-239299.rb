control 'SV-239299' do
  title 'The ESXi host must enable kernel core dumps.'
  desc 'In the event of a system failure, the system must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'check', 'From the vSphere Client, select the ESXi host and right-click. 

If the "Add Diagnostic Partition" option is greyed out, core dumps are configured.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.coredump.partition.get.Invoke()
$esxcli.system.coredump.network.get.Invoke()

The first command prepares for the other two. The second command shows whether an active core dump partition is configured. The third command shows whether a network core dump collector is configured and enabled via the "HostVNic", "NetworkServerIP", "NetworkServerPort", and "Enabled" variables. 

If there is an active core dump partition, via the second command, this is not a finding.

If there is a network core dump collector configured and enabled, this is not a finding.

If there is no core dump partition and no network core dump collector configured, this is a finding.'
  desc 'fix', %q(From the vSphere Client, select the ESXi host and right-click. Select the "Add Diagnostic Partition" option to configure a core dump diagnostic partition.

or

From a PowerCLI command prompt while connected to the ESXi host, run at least one of the following sets of commands:

To configure a core dump partition:

$esxcli = Get-EsxCli -v2
#View available partitions to configure
$esxcli.system.coredump.partition.list.Invoke()
$arguments = $esxcli.system.coredump.partition.set.CreateArgs()
$arguments.partition = "<NAA ID of target partition from output listed previously>"
$esxcli.system.coredump.partition.set.Invoke($arguments)
#You can't set the partition and enable it at the same time so now we can enable it
$arguments = $esxcli.system.coredump.partition.set.CreateArgs()
$arguments.enable = $true
$esxcli.system.coredump.partition.set.Invoke($arguments)

To configure a core dump collector:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.coredump.network.set.CreateArgs()
$arguments.interfacename = "<vmkernel port to use>"
$arguments.serverip = "<collector IP>"
$arguments.serverport = "<collector port>"
$arguments = $esxcli.system.coredump.network.set.Invoke($arguments)
$arguments = $esxcli.system.coredump.network.set.CreateArgs()
$arguments.enable = $true
$arguments = $esxcli.system.coredump.network.set.Invoke($arguments))
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42532r816575_chk'
  tag severity: 'low'
  tag gid: 'V-239299'
  tag rid: 'SV-239299r816576_rule'
  tag stig_id: 'ESXI-67-000044'
  tag gtitle: 'SRG-OS-000269-VMM-000950'
  tag fix_id: 'F-42491r674825_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
