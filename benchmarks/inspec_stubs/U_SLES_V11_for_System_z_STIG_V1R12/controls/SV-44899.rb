control 'SV-44899' do
  title 'The system must restrict the ability to switch to the root user to members of a defined group.'
  desc 'Configuring a supplemental group for users permitted to switch to the root user prevents unauthorized users from accessing the root account, even with knowledge of the root credentials.'
  desc 'check', 'Check that /etc/pam.d/su and /etc/pam.d/su-l use pam_wheel.
# grep pam_wheel /etc/pam.d/su /etc/pam.d/su-l
If pam_wheel is not present, or is commented out, this is a finding.'
  desc 'fix', 'Edit /etc/pam.d/su and /etc/pam.d/su-l 
Uncomment or add a line such as "auth required pam_wheel.so".  If necessary, create a "wheel" group and add administrative users to the group.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42339r1_chk'
  tag severity: 'low'
  tag gid: 'V-22308'
  tag rid: 'SV-44899r1_rule'
  tag stig_id: 'GEN000850'
  tag gtitle: 'GEN000850'
  tag fix_id: 'F-38331r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000009']
  tag nist: ['AC-2 c']
end
