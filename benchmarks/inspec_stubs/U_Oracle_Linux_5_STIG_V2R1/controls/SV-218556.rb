control 'SV-218556' do
  title 'If the system is an anonymous FTP server, it must be isolated to the DMZ network.'
  desc 'Anonymous FTP is a public data service which is only permitted in a server capacity when located on the DMZ network.'
  desc 'check', %q(Use the command "ftp" to connect the system's FTP service. Attempt to log into this host with a user name of anonymous and a password of guest (also try the password of guest@mail.com). If the logon is not successful, this check is Not Applicable.

Ask the SA if the system is located on a DMZ network. If the system is not located on a DMZ network, this is a finding.)
  desc 'fix', 'Remove anonymous ftp capability or move the system to a DMZ network.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20031r562762_chk'
  tag severity: 'medium'
  tag gid: 'V-218556'
  tag rid: 'SV-218556r603259_rule'
  tag stig_id: 'GEN004840'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20029r562763_fix'
  tag 'documentable'
  tag legacy: ['V-4702', 'SV-62925']
  tag cci: ['CCI-000366', 'CCI-000787']
  tag nist: ['CM-6 b', 'IA-4 b']
end
