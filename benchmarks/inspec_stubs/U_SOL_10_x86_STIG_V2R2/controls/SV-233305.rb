control 'SV-233305' do
  title 'The sshd server must bind the X11 forwarding server to the loopback address.'
  desc "Enabling X11 Forwarding on the host can permit a malicious user to secretly open another X11 connection to another remote client during the session and perform unobtrusive activities such as keystroke monitoring. If the X11 services are not required for the system's intended function, they should be disabled or restricted as appropriate to the user's needs.
By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment variable to “localhost”. This prevents remote hosts from connecting to the proxy display."
  desc 'check', 'Determine if the X11 forwarding server is bound to the loopback address.

# grep "^X11UseLocalhost" /etc/ssh/sshd_config

If the output of this command is not “X11UseLocalhost yes”, this is a finding.'
  desc 'fix', 'The root role is required.

Modify the sshd_config file.

# vi /etc/ssh/sshd_config

Locate the line containing:

X11UseLocalhost 

Change it to:

X11UseLocalhost yes

Restart the SSH service.

# svcadm restart svc:/network/ssh'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36500r603293_chk'
  tag severity: 'medium'
  tag gid: 'V-233305'
  tag rid: 'SV-233305r603295_rule'
  tag stig_id: 'GEN005202'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36464r603294_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
