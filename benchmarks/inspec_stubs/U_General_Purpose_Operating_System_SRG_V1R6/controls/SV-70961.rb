control 'SV-70961' do
  title 'Operating systems must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify operating system enforces 24 hours/1 day as the minimum password lifetime. If it does not, this is a finding.'
  desc 'fix', 'Configure operating system to enforce 24 hours/1 day as the minimum password lifetime.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57271r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56701'
  tag rid: 'SV-70961r1_rule'
  tag stig_id: 'SRG-OS-000075-GPOS-00043'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-61597r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
