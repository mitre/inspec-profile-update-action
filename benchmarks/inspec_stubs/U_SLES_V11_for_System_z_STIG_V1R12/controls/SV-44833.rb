control 'SV-44833' do
  title 'The system must display the date and time of the last successful account login upon login.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Check that pam_lastlog is used and not silent, or that the SSH daemon is configured to display last login information.

# grep pam_lastlog /etc/pam.d/sshd
If pam_lastlog is present, and does not have the "silent" option, this is not a finding.

# grep -i PrintLastLog /etc/ssh/sshd_config


If PrintLastLog is not enabled in the configuration either explicitly or by default, this is a finding.'
  desc 'fix', 'Implement pam_lastlog, or enable PrintLastLog in the SSH daemon.

To enable pam_lastlog, add a line such as "session required pam_lastlog.so" to /etc/pam.d/sshd.

To enable PrintLastLog in the SSH daemon, remove any lines disabling this option from /etc/ssh/sshd_config.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42304r1_chk'
  tag severity: 'low'
  tag gid: 'V-22299'
  tag rid: 'SV-44833r1_rule'
  tag stig_id: 'GEN000452'
  tag gtitle: 'GEN000452'
  tag fix_id: 'F-38270r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
