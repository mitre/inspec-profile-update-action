control 'SV-256442' do
  title 'The ESXi host rhttpproxy daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions.'
  desc 'ESXi runs a reverse proxy service called rhttpproxy that front ends internal services and application programming interfaces (APIs) over one HTTPS port by redirecting virtual paths to localhost ports. 

This proxy implements a FIPS 140-2 validated OpenSSL cryptographic module that is in FIPS mode by default. This configuration must be validated and maintained to protect the traffic that rhttpproxy manages.'
  desc 'check', 'From an ESXi shell, run the following command:

# esxcli system security fips140 rhttpproxy get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.security.fips140.rhttpproxy.get.invoke()

Expected result:

Enabled: true

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following command:

# esxcli system security fips140 rhttpproxy set -e true

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.security.fips140.rhttpproxy.set.CreateArgs()
$arguments.enable = $true
$esxcli.system.security.fips140.rhttpproxy.set.Invoke($arguments)'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60117r886105_chk'
  tag severity: 'medium'
  tag gid: 'V-256442'
  tag rid: 'SV-256442r886107_rule'
  tag stig_id: 'ESXI-70-000090'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag fix_id: 'F-60060r886106_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
