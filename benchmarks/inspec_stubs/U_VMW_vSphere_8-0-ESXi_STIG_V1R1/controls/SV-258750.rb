control 'SV-258750' do
  title 'The ESXi host Secure Shell (SSH) daemon must be configured to only use FIPS 140-2 validated ciphers.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. ESXi must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', "From an ESXi shell, run the following command:

# esxcli system ssh server config list -k ciphers

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ciphers'}

Expected result:

ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

If the output matches the ciphers in the expected result or a subset thereof, this is not a finding.

If the ciphers in the output contain any ciphers not listed in the expected result, this is a finding."
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k ciphers -v aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'ciphers'
$arguments.value = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62490r933309_chk'
  tag severity: 'medium'
  tag gid: 'V-258750'
  tag rid: 'SV-258750r933311_rule'
  tag stig_id: 'ESXI-80-000187'
  tag gtitle: 'SRG-OS-000478-VMM-001980'
  tag fix_id: 'F-62399r933310_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
