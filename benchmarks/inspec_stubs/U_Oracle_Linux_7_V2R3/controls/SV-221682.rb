control 'SV-221682' do
  title 'The Oracle Linux operating system must be configured so that passwords are restricted to a 24 hours/1 day minimum lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(Check whether the minimum time period between password changes for each user account is one day or greater.

# awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 24 hours/1 day minimum password lifetime:

# chage -m 1 [user]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23397r419118_chk'
  tag severity: 'medium'
  tag gid: 'V-221682'
  tag rid: 'SV-221682r603260_rule'
  tag stig_id: 'OL07-00-010240'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-23386r419119_fix'
  tag 'documentable'
  tag legacy: ['V-99103', 'SV-108207']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
