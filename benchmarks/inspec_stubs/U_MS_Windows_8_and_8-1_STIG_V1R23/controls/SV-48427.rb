control 'SV-48427' do
  title 'The VPN client on mobile devices must disable split tunneling.'
  desc 'When split tunneling is enabled, device peripherals and other computers communicating with the mobile device may be able to connect to a DoD network  and obtain sensitive information or otherwise compromise DoD information resources.  Disabling split tunneling eliminates the risk associated with this vulnerability.'
  desc 'check', 'Verify the VPN client on mobile devices is configured to prevent split tunneling for connections to DoD networks.  If it is not, this is a finding.

Procedures will vary depending on the VPN client used.'
  desc 'fix', 'Configure the VPN client on mobile devices to prevent split tunneling when connecting to DoD networks.

Procedures will vary depending on the VPN client used.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45096r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36753'
  tag rid: 'SV-48427r2_rule'
  tag stig_id: 'WN08-MO-000002'
  tag gtitle: 'WN08-MO-000002'
  tag fix_id: 'F-41558r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWN-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
