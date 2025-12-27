control 'SV-258738' do
  title 'The ESXi host Secure Shell (SSH) daemon must ignore .rhosts files.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH can emulate the behavior of the obsolete "rsh" command in allowing users to enable insecure access to their accounts via ".rhosts" files.'
  desc 'check', %q(From an ESXi shell, run the following command:

# esxcli system ssh server config list -k ignorerhosts

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ignorerhosts'}

Example result:

ignorerhosts yes

If "ignorerhosts" is not configured to "yes", this is a finding.)
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k ignorerhosts -v yes

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'ignorerhosts'
$arguments.value = 'yes'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62478r933273_chk'
  tag severity: 'medium'
  tag gid: 'V-258738'
  tag rid: 'SV-258738r933275_rule'
  tag stig_id: 'ESXI-80-000052'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag fix_id: 'F-62387r933274_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
