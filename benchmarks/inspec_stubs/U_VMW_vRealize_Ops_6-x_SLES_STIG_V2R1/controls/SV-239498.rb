control 'SV-239498' do
  title 'Users must not be able to change passwords more than once every 24 hours.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(Check the minimum time period between password changes for each user account is "1" day.

# cat /etc/shadow | cut -d ':' -f1,4 | grep -v 1 | grep -v ":$"

If any results are returned, this is a finding.)
  desc 'fix', 'Change the minimum time period between password changes for each [USER] account to "1" day. The command in the check text will give you a list of users that need to be updated to be in compliance.

# passwd -n 1 [USER]'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42731r661943_chk'
  tag severity: 'medium'
  tag gid: 'V-239498'
  tag rid: 'SV-239498r661945_rule'
  tag stig_id: 'VROM-SL-000380'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-42690r661944_fix'
  tag 'documentable'
  tag legacy: ['SV-99117', 'V-88467']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
