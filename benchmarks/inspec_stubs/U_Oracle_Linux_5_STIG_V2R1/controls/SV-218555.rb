control 'SV-218555' do
  title 'Anonymous FTP must not be active on the system unless authorized.'
  desc 'Due to the numerous vulnerabilities inherent in anonymous FTP, it is not recommended. If anonymous FTP must be used on a system, the requirement must be authorized and approved in the system accreditation package.'
  desc 'check', 'Attempt to log into this host with a user name of anonymous and a password of guest (also try the password of guest@mail.com). If the logon is successful and the use of anonymous ftp has not been documented and approved by the IAO, this is a finding.

Procedure:
# ftp localhost
Name: anonymous
530 Guest login not allowed on this machine.'
  desc 'fix', 'Configure the FTP service to not permit anonymous logins.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20030r562759_chk'
  tag severity: 'medium'
  tag gid: 'V-218555'
  tag rid: 'SV-218555r603259_rule'
  tag stig_id: 'GEN004820'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20028r562760_fix'
  tag 'documentable'
  tag legacy: ['V-846', 'SV-62955']
  tag cci: ['CCI-001475', 'CCI-000381']
  tag nist: ['AC-22 c', 'CM-7 a']
end
