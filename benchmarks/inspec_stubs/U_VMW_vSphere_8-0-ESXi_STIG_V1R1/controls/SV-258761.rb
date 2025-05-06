control 'SV-258761' do
  title 'The ESXi host Secure Shell (SSH) daemon must not allow host-based authentication.'
  desc %q(SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH's cryptographic host-based authentication is more secure than ".rhosts" authentication since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization.)
  desc 'check', %q(From an ESXi shell, run the following command:

# esxcli system ssh server config list -k hostbasedauthentication

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'hostbasedauthentication'}

Example result:

hostbasedauthentication no

If "hostbasedauthentication" is not configured to "no", this is a finding.)
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k hostbasedauthentication -v no

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'hostbasedauthentication'
$arguments.value = 'no'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62501r933342_chk'
  tag severity: 'medium'
  tag gid: 'V-258761'
  tag rid: 'SV-258761r933344_rule'
  tag stig_id: 'ESXI-80-000202'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62410r933343_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
