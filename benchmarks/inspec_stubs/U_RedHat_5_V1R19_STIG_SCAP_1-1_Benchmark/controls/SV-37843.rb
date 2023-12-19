control 'SV-37843' do
  title 'The SSH daemon must restrict login ability to specific users and/or groups.'
  desc 'Restricting SSH logins to a limited group of users, such as system administrators, prevents password-guessing and other SSH attacks from reaching system accounts and other accounts not authorized for SSH access.'
  desc 'fix', 'Edit the SSH daemon configuration and add an "AllowGroups" or "AllowUsers" directive specifying the groups and users allowed to have access.

Restart the SSH daemon.
# /sbin/service sshd restart

Alternatively, modify the /etc/pam.d/sshd file to include the line 

account required pam_access.so accessfile=<path to access.conf for sshd>

If the "accessfile" option is not specified the default "access.conf" file will be used. The "access.conf" file must contain the user restriction definitions.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22470'
  tag rid: 'SV-37843r2_rule'
  tag stig_id: 'GEN005521'
  tag gtitle: 'GEN005521'
  tag fix_id: 'F-32309r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
