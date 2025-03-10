control 'SV-233303' do
  title 'X11 forwarding for SSH must be disabled.'
  desc "Enabling X11 Forwarding on the host can permit a malicious user to secretly open another X11 connection to another remote client during the session and perform unobtrusive activities such as keystroke monitoring. If the X11 services are not required for the system's intended function, they should be disabled or restricted as appropriate to the user's needs."
  desc 'check', 'Determine if X11 Forwarding is enabled.

# grep "^X11Forwarding" /etc/ssh/sshd_config

If the output of this command is not “X11Forwarding no”, this is a finding.'
  desc 'fix', 'The root role is required.

Modify the sshd_config file.

# vi /etc/ssh/sshd_config

Locate the line containing:

X11Forwarding 

Change it to:

X11Forwarding no

Restart the SSH service.

# svcadm restart svc:/network/ssh'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36498r622221_chk'
  tag severity: 'medium'
  tag gid: 'V-233303'
  tag rid: 'SV-233303r603289_rule'
  tag stig_id: 'GEN005201'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36462r622222_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
