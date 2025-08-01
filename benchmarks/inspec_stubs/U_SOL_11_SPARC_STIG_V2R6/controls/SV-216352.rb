control 'SV-216352' do
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
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17588r462490_chk'
  tag severity: 'low'
  tag gid: 'V-216352'
  tag rid: 'SV-216352r603267_rule'
  tag stig_id: 'SOL-11.1-040340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17586r462491_fix'
  tag 'documentable'
  tag legacy: ['SV-60971', 'V-48099']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
