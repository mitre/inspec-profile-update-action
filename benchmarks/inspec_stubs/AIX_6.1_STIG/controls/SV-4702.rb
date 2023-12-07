control 'SV-4702' do
  title 'If the system is an anonymous FTP server, it must be isolated to the DMZ network.'
  desc 'Anonymous FTP is a public data service which is only permitted in a server capacity when located on the DMZ network.'
  desc 'check', "Use the command ftp to connect the system's FTP service. Attempt to log into this host with a user name of anonymous and a password of guest (also try the password of guest@mail.com). If the logon is not successful, this check is not applicable.

Ask the SA if the system is located on a DMZ network. If the system is not located on a DMZ network, this is a finding."
  desc 'fix', 'Move the system to a DMZ network.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-712r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4702'
  tag rid: 'SV-4702r2_rule'
  tag stig_id: 'GEN004840'
  tag gtitle: 'GEN004840'
  tag fix_id: 'F-4630r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000787']
  tag nist: ['IA-4 b']
end
