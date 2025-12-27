control 'SV-256384' do
  title 'The ESXi host Secure Shell (SSH) daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions.'
  desc 'OpenSSH on the ESXi host ships with a FIPS 140-2 validated cryptographic module that is enabled by default. For backward compatibility reasons, this can be disabled so this setting can be audited and corrected if necessary.'
  desc 'check', 'From an ESXi shell, run the following command:

# esxcli system security fips140 ssh get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.security.fips140.ssh.get.invoke()

Expected result:

Enabled: true

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following command:

# esxcli system security fips140 ssh set -e true

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
$arguments.enable = $true
$esxcli.system.security.fips140.ssh.set.Invoke($arguments)'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60059r885931_chk'
  tag severity: 'medium'
  tag gid: 'V-256384'
  tag rid: 'SV-256384r885933_rule'
  tag stig_id: 'ESXI-70-000010'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag fix_id: 'F-60002r885932_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
