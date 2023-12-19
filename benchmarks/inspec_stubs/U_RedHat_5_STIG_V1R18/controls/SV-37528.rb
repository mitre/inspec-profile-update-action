control 'SV-37528' do
  title 'If the system is an anonymous FTP server, it must be isolated to the DMZ network.'
  desc 'Anonymous FTP is a public data service which is only permitted in a server capacity when located on the DMZ network.'
  desc 'check', %q(Use the command "ftp" to connect the system's FTP service. Attempt to log into this host with a user name of anonymous and a password of guest (also try the password of guest@mail.com). If the logon is not successful, this check is Not Applicable.

Ask the SA if the system is located on a DMZ network. If the system is not located on a DMZ network, this is a finding.)
  desc 'fix', 'Remove anonymous ftp capability or move the system to a DMZ network.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4702'
  tag rid: 'SV-37528r1_rule'
  tag stig_id: 'GEN004840'
  tag gtitle: 'GEN004840'
  tag fix_id: 'F-31442r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000787']
  tag nist: ['IA-4 b']
end
