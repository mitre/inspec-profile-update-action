control 'SV-209052' do
  title 'The operating system, upon successful logon/access, must display to the user the number of unsuccessful logon/access attempts since the last successful logon/access.'
  desc 'Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.'
  desc 'check', 'To ensure that last logon/access notification is configured correctly, run the following command:

# grep pam_lastlog.so /etc/pam.d/system-auth

The output should show output "showfailed". If that is not the case, this is a finding.'
  desc 'fix', 'To configure the system to notify users of last logon/access using "pam_lastlog", add the following line immediately after "session required pam_limits.so":

session required pam_lastlog.so showfailed'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9305r357941_chk'
  tag severity: 'medium'
  tag gid: 'V-209052'
  tag rid: 'SV-209052r793773_rule'
  tag stig_id: 'OL6-00-000372'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9305r357942_fix'
  tag 'documentable'
  tag legacy: ['V-59375', 'SV-73805']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
