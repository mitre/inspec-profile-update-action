control 'SV-71077' do
  title 'The operating system must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.'
  desc 'Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

Requires further clarification from NIST.'
  desc 'check', 'Verify the operating system implements multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57387r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56817'
  tag rid: 'SV-71077r1_rule'
  tag stig_id: 'SRG-OS-000375-GPOS-00160'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-61713r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
end
