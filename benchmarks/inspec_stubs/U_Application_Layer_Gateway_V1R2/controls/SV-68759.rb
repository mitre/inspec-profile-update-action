control 'SV-68759' do
  title 'The ALG providing user authentication intermediary services must implement multifactor authentication for remote access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'For remote access to non-privileged accounts, the purpose of requiring a device that is separate from the information system gaining access for one of the factors during multifactor authentication is to reduce the likelihood of compromising authentication credentials stored on the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

An example of compliance with this requirement is the use of a one-time password token and PIN coupled with a password; or the use of a CAC/PIV card and PIN coupled with a password.'
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG implements multifactor authentication for remote access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.

If the ALG does not implement multifactor authentication for remote access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the ALG to implement multifactor authentication for remote access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55129r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54513'
  tag rid: 'SV-68759r2_rule'
  tag stig_id: 'SRG-NET-000339-ALG-000090'
  tag gtitle: 'SRG-NET-000339-ALG-000090'
  tag fix_id: 'F-59367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001951']
  tag nist: ['IA-2 (11)']
end
