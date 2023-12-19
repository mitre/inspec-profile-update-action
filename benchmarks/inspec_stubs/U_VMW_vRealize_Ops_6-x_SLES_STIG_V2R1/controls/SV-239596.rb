control 'SV-239596' do
  title 'The SLES for vRealize must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Check the "pam_tally2" configuration:

# more /etc/pam.d/common-auth

Confirm the following line is configured:

auth required pam_tally2.so deny=3 onerr=fail even_deny_root unlock_ti
me=86400 root_unlock_time=300

# more /etc/pam.d/common-account

Confirm the following line is configured:

account required pam_tally2.so

If no such lines are found, this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/common-auth" file and add the following line:

auth required pam_tally2.so deny=3 onerr=fail even_deny_root unlock_time=86400 root_unlock_time=300 

Edit "/etc/pam.d/common-account" file and add the following line:

account required pam_tally2.so'
  impact 0.3
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42829r662237_chk'
  tag severity: 'low'
  tag gid: 'V-239596'
  tag rid: 'SV-239596r662239_rule'
  tag stig_id: 'VROM-SL-001010'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-42788r662238_fix'
  tag 'documentable'
  tag legacy: ['SV-99313', 'V-88663']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
