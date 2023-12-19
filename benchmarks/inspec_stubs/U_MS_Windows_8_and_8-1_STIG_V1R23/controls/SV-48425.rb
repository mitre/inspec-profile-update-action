control 'SV-48425' do
  title 'The VPN client on mobile devices must use DoD approved multi-factor authentication tokens (e.g., Common Access Card (CAC) for unclassified systems) when connecting to DoD networks.'
  desc 'VPNs are vulnerable to attack if they are not supported by strong authentication.   An adversary may be able gain access to network resources and sensitive information if they can compromise the authentication process.  DoD approved multi-factor authentication tokens (e.g., Common Access Card (CAC) for unclassified systems) is strong cryptographic two-factor authentication that greatly mitigates the risk of VPN authentication breaches.'
  desc 'check', 'Verify the VPN client on mobile devices is configured to use DoD approved multi-factor authentication tokens (e.g., Common Access Card (CAC) for unclassified systems) for connections to DoD networks.  If it is not, this is a finding.

Procedures will vary depending on the VPN client used.'
  desc 'fix', 'Configure the VPN client on mobile devices to use DoD approved multi-factor authentication tokens (e.g., Common Access Card (CAC) for unclassified systems) when connecting to DoD networks.

Procedures will vary depending on the VPN client used.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45095r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36752'
  tag rid: 'SV-48425r2_rule'
  tag stig_id: 'WN08-MO-000001'
  tag gtitle: 'WN08-MO-000001'
  tag fix_id: 'F-41556r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWN-1'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
