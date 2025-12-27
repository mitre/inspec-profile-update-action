control 'SV-68761' do
  title 'The ALG providing user authentication intermediary services must implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'For remote access to privileged accounts, the purpose of requiring a device that is separate from the information system gaining access for one of the factors during multifactor authentication is to reduce the likelihood of compromising authentication credentials stored on the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.'
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.

If the ALG does not implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the ALG to implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55131r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54515'
  tag rid: 'SV-68761r1_rule'
  tag stig_id: 'SRG-NET-000340-ALG-000091'
  tag gtitle: 'SRG-NET-000340-ALG-000091'
  tag fix_id: 'F-59369r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
end
