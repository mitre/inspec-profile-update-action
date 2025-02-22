control 'SV-226947' do
  title 'If the system is an anonymous FTP server, it must be isolated to the DMZ network.'
  desc 'Anonymous FTP is a public data service which is only permitted in a server capacity when located on the DMZ network.'
  desc 'check', "Use the command ftp to connect the system's FTP service. Attempt to log into this host with a user name of anonymous and a password of guest (also try the password of guest@mail.com). If the logon is not successful, this check is not applicable.

Ask the SA if the system is located on a DMZ network. If the system is not located on a DMZ network, this is a finding."
  desc 'fix', 'Move the system to a DMZ network.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29109r485168_chk'
  tag severity: 'medium'
  tag gid: 'V-226947'
  tag rid: 'SV-226947r603265_rule'
  tag stig_id: 'GEN004840'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29097r485169_fix'
  tag 'documentable'
  tag legacy: ['V-4702', 'SV-4702']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
