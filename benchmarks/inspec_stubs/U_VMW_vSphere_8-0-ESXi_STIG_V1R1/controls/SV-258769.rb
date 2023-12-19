control 'SV-258769' do
  title 'The ESXi host must configure the firewall to block network traffic by default.'
  desc 'In addition to service-specific firewall rules, ESXi has a default firewall rule policy to allow or deny incoming and outgoing traffic. Reduce the risk of attack by ensuring this is set to deny incoming and outgoing traffic.'
  desc 'check', 'From an ESXi shell, run the following command:

# esxcli network firewall get

If the "Default Action" does not equal "DROP", this is a finding.
If "Enabled" does not equal "true", this is a finding.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHostFirewallDefaultPolicy

If the Incoming or Outgoing policies are "True", this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following command:

# esxcli network firewall set --default-action=false

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHostFirewallDefaultPolicy | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62509r933366_chk'
  tag severity: 'medium'
  tag gid: 'V-258769'
  tag rid: 'SV-258769r933368_rule'
  tag stig_id: 'ESXI-80-000214'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62418r933367_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
