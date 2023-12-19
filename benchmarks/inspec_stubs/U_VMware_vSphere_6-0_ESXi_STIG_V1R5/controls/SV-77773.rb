control 'SV-77773' do
  title 'The system must configure the firewall to block network traffic by default.'
  desc 'In addition to service specific firewall rules ESXi has a default firewall rule policy to allow or deny incoming and outgoing traffic.  Reduce the risk of attack by making sure this is set to deny incoming and outgoing traffic.'
  desc 'check', 'From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHostFirewallDefaultPolicy

If the Incoming or Outgoing policies are True, this is a finding.'
  desc 'fix', 'From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHostFirewallDefaultPolicy | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64017r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63283'
  tag rid: 'SV-77773r1_rule'
  tag stig_id: 'ESXI-06-000057'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69201r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
