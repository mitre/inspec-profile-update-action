control 'SV-258764' do
  title 'The ESXi host Secure Shell (SSH) daemon must not permit tunnels.'
  desc 'OpenSSH has the ability to create network tunnels (layer 2 and layer 3) over an SSH connection. This function can provide similar convenience to a virtual private network (VPN) with the similar risk of providing a path to circumvent firewalls and network Access Control Lists (ACLs).'
  desc 'check', %q(From an ESXi shell, run the following command:

# esxcli system ssh server config list -k permittunnel

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permittunnel'}

Example result:

permittunnel no

If "permittunnel" is not configured to "no", this is a finding.)
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k permittunnel -v no

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'permittunnel'
$arguments.value = 'no'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62504r933351_chk'
  tag severity: 'medium'
  tag gid: 'V-258764'
  tag rid: 'SV-258764r933353_rule'
  tag stig_id: 'ESXI-80-000209'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62413r933352_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
