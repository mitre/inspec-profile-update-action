control 'SV-219178' do
  title 'The Ubuntu operating system must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify that the Ubuntu operating system enforces a 24 hours/1 day minimum password lifetime for new user accounts by running the following command:

# grep -i pass_min_days /etc/login.defs

PASS_MIN_DAYS 1

If the "PASS_MIN_DAYS" parameter value is less than 1, or commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to enforce a 24 hours/1 day minimum password lifetime.

Add, or modify the following line in the "/etc/login.defs" file:

PASS_MIN_DAYS 1'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20903r304862_chk'
  tag severity: 'low'
  tag gid: 'V-219178'
  tag rid: 'SV-219178r610963_rule'
  tag stig_id: 'UBTU-18-010106'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-20902r304863_fix'
  tag 'documentable'
  tag legacy: ['SV-109687', 'V-100583']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
