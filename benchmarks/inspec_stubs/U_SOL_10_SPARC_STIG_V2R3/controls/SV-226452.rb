control 'SV-226452' do
  title 'The system must display the date and time of the last successful account login upon login.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Determine if the system displays the date and time of the last successful login upon logging in. This can be accomplished by logging into the system and verifying whether or not the necessary information is displayed. If the system does not provide this information upon login, this is a finding.

Last login information is provided automatically by the login(1) program for telnet and console login sessions.

Verify the SSH daemon is configured to display last login information.

# grep -i PrintLastLog /etc/ssh/sshd_config
If PrintLastLog is present in the configuration and not disabled, this is not a finding. Otherwise, this is a finding.'
  desc 'fix', 'Configure the system to display the date and time of the last successful login upon logging in.

Enable PrintLastLog in the SSH daemon.

To enable PrintLastLog in the SSH daemon, remove any lines disabling this option from /etc/ssh/sshd_config.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28613r482723_chk'
  tag severity: 'low'
  tag gid: 'V-226452'
  tag rid: 'SV-226452r603265_rule'
  tag stig_id: 'GEN000452'
  tag gtitle: 'SRG-OS-000025'
  tag fix_id: 'F-28601r482724_fix'
  tag 'documentable'
  tag legacy: ['SV-26310', 'V-22299']
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
