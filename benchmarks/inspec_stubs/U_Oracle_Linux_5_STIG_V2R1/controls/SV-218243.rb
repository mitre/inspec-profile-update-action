control 'SV-218243' do
  title 'The system must restrict the ability to switch to the root user to members of a defined group.'
  desc 'Configuring a supplemental group for users permitted to switch to the root user prevents unauthorized users from accessing the root account, even with knowledge of the root credentials.'
  desc 'check', 'Check /etc/pam.d/su uses pam_wheel.
# grep pam_wheel /etc/pam.d/su

If pam_wheel is not present, or is commented out, this is a finding.'
  desc 'fix', 'Edit /etc/pam.d/su and uncomment or add a line such as "auth required pam_wheel.so". If necessary, create a "wheel" group and add administrative users to the group.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19718r561578_chk'
  tag severity: 'low'
  tag gid: 'V-218243'
  tag rid: 'SV-218243r603259_rule'
  tag stig_id: 'GEN000850'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19716r561579_fix'
  tag 'documentable'
  tag legacy: ['V-22308', 'SV-64327']
  tag cci: ['CCI-000009', 'CCI-002169']
  tag nist: ['AC-2 c', 'AC-3 (7)']
end
