control 'SV-233308' do
  title 'The SUSE operating system SSH daemon must prevent remote hosts from connecting to the proxy display.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address. By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DIPSLAY environment variable to localhost. This prevents remote hosts from connecting to the proxy display.'
  desc 'check', 'Verify the SUSE operating system SSH daemon prevents remote hosts from connecting to the proxy display.

Check the SSH X11UseLocalhost setting with the following command:

# sudo grep -i x11uselocalhost /etc/ssh/sshd_config
X11UseLocalhost yes

If the "X11UseLocalhost" keyword is set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system SSH daemon to prevent remote hosts from connecting to the proxy display.

Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11UseLocalhost" keyword and set its value to "yes" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

X11UseLocalhost yes'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-36503r622236_chk'
  tag severity: 'medium'
  tag gid: 'V-233308'
  tag rid: 'SV-233308r603331_rule'
  tag stig_id: 'SLES-12-030261'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36467r622237_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
