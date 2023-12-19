control 'SV-37843' do
  title 'The SSH daemon must restrict login ability to specific users and/or groups.'
  desc 'Restricting SSH logins to a limited group of users, such as system administrators, prevents password-guessing and other SSH attacks from reaching system accounts and other accounts not authorized for SSH access.'
  desc 'check', %q(There are two ways in which access to SSH may restrict users or groups.

Check if /etc/pam.d/sshd is configured to require daemon style login control.
# grep pam_access.so /etc/pam.d/sshd|grep "required"|grep "account"| grep -v '^#' 
If no lines are returned, sshd is not configured to use pam_access.

Check the SSH daemon configuration for the AllowGroups setting.
# egrep -i "AllowGroups|AllowUsers" /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, sshd is not configured to limit access to users/groups.

If sshd is not configured to limit access either through pam_access or the use "AllowUsers" or "Allowgroups", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add an "AllowGroups" or "AllowUsers" directive specifying the groups and users allowed to have access.

Restart the SSH daemon.
# /sbin/service sshd restart

Alternatively, modify the /etc/pam.d/sshd file to include the line 

account required pam_access.so accessfile=<path to access.conf for sshd>

If the "accessfile" option is not specified the default "access.conf" file will be used. The "access.conf" file must contain the user restriction definitions.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37041r1_chk'
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
