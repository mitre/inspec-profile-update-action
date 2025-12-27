control 'SV-71015' do
  title 'The operating system must use multifactor authentication for network access to privileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
1) something a user knows (e.g., password/PIN);
2) something a user has (e.g., cryptographic identification device, token); and
3) something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the operating system uses multifactor authentication for network access to privileged accounts. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to use multifactor authentication for network access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57325r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56755'
  tag rid: 'SV-71015r1_rule'
  tag stig_id: 'SRG-OS-000105-GPOS-00052'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-61651r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
