control 'SV-38768' do
  title 'Users must not be able to change passwords more than once every 24 hours.'
  desc 'The ability to change passwords frequently facilitates users reusing the same password. This can result in users effectively never changing their passwords. This would be accomplished by users changing their passwords when required and then immediately changing it to the original value.'
  desc 'check', 'Check the minage field for each user.
# /usr/sbin/lsuser -a minage ALL

If the minage field is less than 1 for any user, this is a finding.'
  desc 'fix', 'Use SMIT or the chsec command to set the minimum password age to 1 week.

# chsec -f /etc/security/user -s default -a minage=1 
# chsec -f /etc/security/user -s <user id> -a minage=1

OR

# smitty chuser'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36689r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1032'
  tag rid: 'SV-38768r1_rule'
  tag stig_id: 'GEN000540'
  tag gtitle: 'GEN000540'
  tag fix_id: 'F-33201r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
