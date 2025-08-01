control 'SV-207480' do
  title 'The VMM must implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'Using an authentication device, such as a CAC or token that is separate from the VMM, ensures that even if the VMM is compromised, that compromise will not affect credentials stored on the authentication device. 

Multifactor solutions that require devices separate from VMMs gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is defined as a VMM account with authorizations of a privileged user.

Remote access is access to DoD non-public VMMs by an authorized user (or a VMM) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.'
  desc 'check', 'Verify the VMM implements multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7737r365844_chk'
  tag severity: 'medium'
  tag gid: 'V-207480'
  tag rid: 'SV-207480r854654_rule'
  tag stig_id: 'SRG-OS-000375-VMM-001510'
  tag gtitle: 'SRG-OS-000375'
  tag fix_id: 'F-7737r365845_fix'
  tag 'documentable'
  tag legacy: ['V-57161', 'SV-71421']
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
end
