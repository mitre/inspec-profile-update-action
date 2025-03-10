control 'SV-207389' do
  title 'The VMM must use multifactor authentication for local access to privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication is defined as using two or more factors to achieve authentication.

Factors include:
(i) Something you know (e.g., password/PIN);
(ii) Something you have (e.g., cryptographic identification device, token); or
(iii) Something you are (e.g., biometric).

A privileged account is defined as a VMM account with authorizations of a privileged user.

Local access is defined as access to an organizational VMM by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the VMM uses multifactor authentication for local access to privileged accounts.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to use multifactor authentication for local access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7646r365577_chk'
  tag severity: 'medium'
  tag gid: 'V-207389'
  tag rid: 'SV-207389r378856_rule'
  tag stig_id: 'SRG-OS-000107-VMM-000530'
  tag gtitle: 'SRG-OS-000107'
  tag fix_id: 'F-7646r365578_fix'
  tag 'documentable'
  tag legacy: ['V-56979', 'SV-71239']
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
