control 'SV-216115' do
  title 'Consecutive login attempts for SSH must be limited to 3.'
  desc 'Setting the authentication login limit to a low value will disconnect the attacker and force a reconnect, which severely limits the speed of such brute-force attacks.'
  desc 'check', 'Determine if consecutive login attempts are limited to 3.

# grep "^MaxAuthTries" /etc/ssh/sshd_config | grep -v Log

If the output of this command is not:

MaxAuthTries 6

this is a finding.

Note: Solaris SSH MaxAuthTries of 6 maps to 3 actual failed attempts.'
  desc 'fix', 'The root role is required.

Modify the sshd_config file.

# pfedit /etc/ssh/sshd_config

Locate the line containing:

MaxAuthTries 

Change it to:

MaxAuthTries 6

Restart the SSH service.

# svcadm restart svc:/network/ssh

Note: Solaris SSH MaxAuthTries of 6 maps to 3 actual failed attempts.'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17353r462478_chk'
  tag severity: 'low'
  tag gid: 'V-216115'
  tag rid: 'SV-216115r603268_rule'
  tag stig_id: 'SOL-11.1-040340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17351r462479_fix'
  tag 'documentable'
  tag legacy: ['V-48099', 'SV-60971']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
