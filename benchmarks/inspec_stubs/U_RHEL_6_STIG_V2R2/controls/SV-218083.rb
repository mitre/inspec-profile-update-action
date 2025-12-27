control 'SV-218083' do
  title 'The operating system, upon successful logon/access, must display to the user the number of unsuccessful logon/access attempts since the last successful logon/access.'
  desc 'Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.'
  desc 'check', 'To ensure that last logon/access notification is configured correctly, run the following command:

# grep pam_lastlog.so /etc/pam.d/system-auth
session      required     pam_lastlog.so     showfailed

If the output does not have the "showfailed" option, this is a finding.

If the output contains the "silent" option, this is a finding.'
  desc 'fix', 'To configure the system to notify users of last logon/access using "pam_lastlog", add the following line immediately after "session required pam_limits.so":

session required pam_lastlog.so showfailed'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19564r377264_chk'
  tag severity: 'medium'
  tag gid: 'V-218083'
  tag rid: 'SV-218083r603264_rule'
  tag stig_id: 'RHEL-06-000372'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19562r377265_fix'
  tag 'documentable'
  tag legacy: ['SV-66089', 'V-51875']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
