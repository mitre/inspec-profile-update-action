control 'SV-233779' do
  title 'The Ubuntu operating system must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.'
  desc "The security risk of using X11 forwarding is that the client's X11 display server may be exposed to attack when the SSH client requests forwarding. A system administrator may have a stance in which they want to protect clients that may expose themselves to attack by unwittingly requesting X11 forwarding, which can warrant a ''no'' setting.
X11 forwarding should be enabled with caution. Users with the ability to bypass file permissions on the remote host (for the user's X11 authorization database) can access the local X11 display through the forwarded connection. An attacker may then be able to perform activities such as keystroke monitoring if the ForwardX11Trusted option is also enabled.
If X11 services are not required for the system's intended function, they should be disabled or restricted as appropriate to the system’s needs."
  desc 'check', 'Verify that X11Forwarding is disabled with the following command:

# grep -i x11forwarding /etc/ssh/sshd_config | grep -v "^#"

X11Forwarding no

If the "X11Forwarding" keyword is set to "yes" and is not documented with the Information System Security Officer (ISSO) as an operational requirement or is missing, this is a finding.'
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11Forwarding" keyword and set its value to "no" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

X11Forwarding no

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-36965r621617_chk'
  tag severity: 'medium'
  tag gid: 'V-233779'
  tag rid: 'SV-233779r610963_rule'
  tag stig_id: 'UBTU-18-010418'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33199r568412_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
