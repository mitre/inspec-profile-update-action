control 'SV-253065' do
  title 'TOSS must not have the rsh-server package installed.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.

'
  desc 'check', 'Check to see if the rsh-server package is installed with the following command:

$ sudo yum list installed rsh-server

If the rsh-server package is installed, this is a finding.'
  desc 'fix', 'Configure the operating system to disable nonessential capabilities by removing the rsh-server package from the system with the following command:

$ sudo yum remove rsh-server'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56518r824865_chk'
  tag severity: 'medium'
  tag gid: 'V-253065'
  tag rid: 'SV-253065r824867_rule'
  tag stig_id: 'TOSS-04-040100'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-56468r824866_fix'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000095-GPOS-00049']
  tag 'documentable'
  tag cci: ['CCI-000197', 'CCI-000381']
  tag nist: ['IA-5 (1) (c)', 'CM-7 a']
end
