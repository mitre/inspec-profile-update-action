control 'SV-226946' do
  title 'Anonymous FTP must not be active on the system unless authorized.'
  desc 'Due to the numerous vulnerabilities inherent in anonymous FTP, it is recommended that it not be used. If anonymous FTP must be used on a system, the requirement must be authorized and approved in the system accreditation package.'
  desc 'check', 'Attempt to log into this host with a user name of anonymous and a password of guest (also try the password of guest@mail.com). If the logon is successful, this is a finding.

Procedure:
# ftp localhost
Name: anonymous
530 Guest login not allowed on this machine.'
  desc 'fix', 'Configure the FTP service to not permit anonymous logins.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29108r485165_chk'
  tag severity: 'medium'
  tag gid: 'V-226946'
  tag rid: 'SV-226946r603265_rule'
  tag stig_id: 'GEN004820'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29096r485166_fix'
  tag 'documentable'
  tag legacy: ['V-846', 'SV-846']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
