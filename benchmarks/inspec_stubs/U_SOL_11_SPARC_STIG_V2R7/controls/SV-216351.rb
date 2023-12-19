control 'SV-216351' do
  title 'X11 forwarding for SSH must be disabled.'
  desc "As enabling X11 Forwarding on the host can permit a malicious user to secretly open another X11 connection to another remote client during the session and perform unobtrusive activities such as keystroke monitoring, if the X11 services are not required for the system's intended function, they should be disabled or restricted as appropriate to the user's needs."
  desc 'check', 'Determine if X11 Forwarding is enabled.

# grep "^X11Forwarding" /etc/ssh/sshd_config

If the output of this command is not:

X11Forwarding no

this is a finding.'
  desc 'fix', 'The root role is required.

Modify the sshd_config file.

# pfedit /etc/ssh/sshd_config

Locate the line containing:

X11Forwarding 

Change it to:

X11Forwarding no

Restart the SSH service.

# svcadm restart svc:/network/ssh'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17587r371141_chk'
  tag severity: 'medium'
  tag gid: 'V-216351'
  tag rid: 'SV-216351r603267_rule'
  tag stig_id: 'SOL-11.1-040330'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17585r371142_fix'
  tag 'documentable'
  tag legacy: ['SV-60965', 'V-48093']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
