control 'SV-71017' do
  title 'The operating system must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication.

Factors include: 
1) Something you know (e.g., password/PIN);
2) Something you have (e.g., cryptographic identification device, token); and
3) Something you are (e.g., biometric).

A non-privileged account is any information system account with authorizations of a non-privileged user.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the operating system uses multifactor authentication for network access to non-privileged accounts. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to use multifactor authentication for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57327r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56757'
  tag rid: 'SV-71017r1_rule'
  tag stig_id: 'SRG-OS-000106-GPOS-00053'
  tag gtitle: 'SRG-OS-000106-GPOS-00053'
  tag fix_id: 'F-61653r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
