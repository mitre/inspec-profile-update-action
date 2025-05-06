control 'SV-70835' do
  title 'The operating system must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically removes or disables local temporary user accounts after 72 hours. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically remove or disable local temporary user accounts after 72 hours.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57143r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56575'
  tag rid: 'SV-70835r1_rule'
  tag stig_id: 'SRG-OS-000002-GPOS-00002'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-61469r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
