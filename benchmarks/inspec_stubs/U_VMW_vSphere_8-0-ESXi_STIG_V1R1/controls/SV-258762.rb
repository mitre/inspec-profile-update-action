control 'SV-258762' do
  title 'The ESXi host Secure Shell (SSH) daemon must not permit user environment settings.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations. Users must not be able to present environment options to the SSH daemon.'
  desc 'check', %q(From an ESXi shell, run the following command:

# esxcli system ssh server config list -k permituserenvironment

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permituserenvironment'}

Example result:

permituserenvironment no

If "permituserenvironment" is not configured to "no", this is a finding.)
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k permituserenvironment -v no

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'permituserenvironment'
$arguments.value = 'no'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62502r933345_chk'
  tag severity: 'medium'
  tag gid: 'V-258762'
  tag rid: 'SV-258762r933347_rule'
  tag stig_id: 'ESXI-80-000204'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62411r933346_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
