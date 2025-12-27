control 'SV-207656' do
  title 'The ESXi host must configure the firewall to block network traffic by default.'
  desc 'In addition to service specific firewall rules ESXi has a default firewall rule policy to allow or deny incoming and outgoing traffic.  Reduce the risk of attack by making sure this is set to deny incoming and outgoing traffic.'
  desc 'check', 'From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHostFirewallDefaultPolicy

If the Incoming or Outgoing policies are True, this is a finding.'
  desc 'fix', 'From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHostFirewallDefaultPolicy | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7911r364367_chk'
  tag severity: 'medium'
  tag gid: 'V-207656'
  tag rid: 'SV-207656r388482_rule'
  tag stig_id: 'ESXI-65-000057'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7911r364368_fix'
  tag 'documentable'
  tag legacy: ['SV-104147', 'V-94061']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
