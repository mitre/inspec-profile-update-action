control 'SV-258785' do
  title 'The ESXi host Secure Shell (SSH) daemon must disable port forwarding.'
  desc 'While enabling Transmission Control Protocol (TCP) tunnels is a valuable function of sshd, this feature is not appropriate for use on the ESXi hypervisor.'
  desc 'check', %q(From an ESXi shell, run the following command:

# esxcli system ssh server config list -k allowtcpforwarding

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'allowtcpforwarding'}

Example result:

allowtcpforwarding no

If "allowtcpforwarding" is not configured to "no", this is a finding.)
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k allowtcpforwarding -v no

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'allowtcpforwarding'
$arguments.value = 'no'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62525r933414_chk'
  tag severity: 'medium'
  tag gid: 'V-258785'
  tag rid: 'SV-258785r933416_rule'
  tag stig_id: 'ESXI-80-000230'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62434r933415_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
