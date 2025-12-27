control 'SV-71019' do
  title 'The operating system must use multifactor authentication for local access to privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication is defined as using two or more factors to achieve authentication.

Factors include: 
1) Something you know (e.g., password/PIN); 
2) Something you have (e.g., cryptographic identification device, token); and
3) Something you are (e.g., biometric).

A privileged account is defined as an operating system account with authorizations of a privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the operating system uses multifactor authentication for local access to privileged accounts. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to use multifactor authentication for local access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57329r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56759'
  tag rid: 'SV-71019r1_rule'
  tag stig_id: 'SRG-OS-000107-GPOS-00054'
  tag gtitle: 'SRG-OS-000107-GPOS-00054'
  tag fix_id: 'F-61655r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
