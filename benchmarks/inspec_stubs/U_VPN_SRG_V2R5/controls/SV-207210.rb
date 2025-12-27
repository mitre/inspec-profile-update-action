control 'SV-207210' do
  title 'The VPN Client must implement multifactor authentication for network access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A non-privileged account is any information system account with authorizations of a non-privileged user.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Verify the VPN Client implements multifactor authentication for network access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.

If the VPN Client does not implement multifactor authentication for network access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access, this is a finding.'
  desc 'fix', 'Configure the VPN Client to implement multifactor authentication for network access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7470r378251_chk'
  tag severity: 'medium'
  tag gid: 'V-207210'
  tag rid: 'SV-207210r856698_rule'
  tag stig_id: 'SRG-NET-000145-VPN-000510'
  tag gtitle: 'SRG-NET-000145'
  tag fix_id: 'F-7470r378252_fix'
  tag 'documentable'
  tag legacy: ['V-97091', 'SV-106229']
  tag cci: ['CCI-001939']
  tag nist: ['IA-2 (7)']
end
