control 'SV-207378' do
  title 'The VMM must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify the VMM enforces 24 hours/1 day as the minimum password lifetime.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce 24 hours/1 day as the minimum password lifetime.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7635r365544_chk'
  tag severity: 'medium'
  tag gid: 'V-207378'
  tag rid: 'SV-207378r378757_rule'
  tag stig_id: 'SRG-OS-000075-VMM-000420'
  tag gtitle: 'SRG-OS-000075'
  tag fix_id: 'F-7635r365545_fix'
  tag 'documentable'
  tag legacy: ['V-56947', 'SV-71207']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
