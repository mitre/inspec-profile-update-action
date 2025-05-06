control 'SV-207232' do
  title 'The VPN Gateway must notify the user, upon successful logon (access), of the organization-defined information to be included in addition to the date and time of the last logon (access).'
  desc 'Users need to be aware of activity that occurs regarding their account. Providing users with information deemed important by the organization may aid in the discovery of unauthorized access or thwart a potential attacker.

Organizations should consider the risks to the specific information system being accessed and the threats presented by the device to the environment when configuring this option. An excessive or unnecessary amount of information presented to the user at logon is not recommended.

This requirement applies to VPN gateways that have the concept of a user account and have the login function residing on the VPN gateway.'
  desc 'check', 'Verity the VPN Gateway notifies the user, upon successful logon (access), of the organization-defined information to be included in addition to the date and time of the last logon (access).

If the VPN Gateway does not notify the user, upon successful logon (access), of the organization-defined information to be included in addition to the date and time of the last logon (access), this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to notify the user, upon successful logon (access), of the organization-defined information to be included in addition to the date and time of the last logon (access).'
  impact 0.3
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7492r378317_chk'
  tag severity: 'low'
  tag gid: 'V-207232'
  tag rid: 'SV-207232r856704_rule'
  tag stig_id: 'SRG-NET-000330-VPN-001220'
  tag gtitle: 'SRG-NET-000330'
  tag fix_id: 'F-7492r378318_fix'
  tag 'documentable'
  tag legacy: ['V-97143', 'SV-106281']
  tag cci: ['CCI-002250']
  tag nist: ['AC-9 (4)']
end
