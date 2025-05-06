control 'SV-207387' do
  title 'The VMM must use multifactor authentication for network access to privileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:
(i) something a user knows (e.g., password/PIN);
(ii) something a user has (e.g., cryptographic identification device, token); or
(iii) something a user is (e.g., biometric).

A privileged account is defined as a VMM account with authorizations of a privileged user.

Network access is defined as access to a VMM by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the VMM uses multifactor authentication for network access to privileged accounts.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to use multifactor authentication for network access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7644r365571_chk'
  tag severity: 'medium'
  tag gid: 'V-207387'
  tag rid: 'SV-207387r378850_rule'
  tag stig_id: 'SRG-OS-000105-VMM-000510'
  tag gtitle: 'SRG-OS-000105'
  tag fix_id: 'F-7644r365572_fix'
  tag 'documentable'
  tag legacy: ['V-56965', 'SV-71225']
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
