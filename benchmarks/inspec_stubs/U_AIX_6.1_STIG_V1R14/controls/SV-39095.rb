control 'SV-39095' do
  title 'The system must display the date and time of the last successful account login upon login.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Determine if the system displays the date and time of the last successful login upon logging in. This can be accomplished by logging into the system and verifying whether or not the necessary information is displayed. If the system does not provide this information upon login, this is a finding.

Verify the SSH daemon is configured to display last login information.
# cat /etc/ssh/sshd_config | grep -i PrintLastLog

If PrintLastLog is disabled, this is a finding.'
  desc 'fix', 'Configure the system to display the date and time of the last successful login upon logging in. Consult OS documentation for the configuration procedure.

Enable PrintLastLog in the SSH daemon. To enable PrintLastLog in the SSH daemon, remove any comment disabling this option from /etc/ssh/sshd_config. The line should look like: "PrintLastLog yes".

Restart sshd.
# kill -1 <PID of sshd>'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38079r2_chk'
  tag severity: 'low'
  tag gid: 'V-22299'
  tag rid: 'SV-39095r1_rule'
  tag stig_id: 'GEN000452'
  tag gtitle: 'GEN000452'
  tag fix_id: 'F-33343r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
