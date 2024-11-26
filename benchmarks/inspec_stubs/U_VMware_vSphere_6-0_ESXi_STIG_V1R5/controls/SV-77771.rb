control 'SV-77771' do
  title 'The system must configure the firewall to restrict access to services running on the host.'
  desc 'Unrestricted access to services running on an ESXi host can expose a host to outside attacks and unauthorized access. Reduce the risk by configuring the ESXi firewall to only allow access from authorized networks.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Security Profile.  Under the Firewall section select properties and for each enabled service click Firewall and review the allowed IPs. 

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostFirewallException | Where {$_.Enabled -eq $true} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}}

If for an enabled service "Allow connections from any IP address" is selected, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Security Profile.  Under the Firewall section select properties and for each enabled service click the "Only allow connections from the following networks" option and input the site specific network(s). 

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

$esxcli = Get-EsxCli
#This disables the allow all rule for the target service
$esxcli.network.firewall.ruleset.set($false,$true,"sshServer")
$esxcli.network.firewall.ruleset.allowedip.add("192.168.0.0/24","sshServer")

This must be done for each enabled service.'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64015r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63281'
  tag rid: 'SV-77771r1_rule'
  tag stig_id: 'ESXI-06-000056'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
