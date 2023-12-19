control 'SV-37526' do
  title 'Anonymous FTP must not be active on the system unless authorized.'
  desc 'Due to the numerous vulnerabilities inherent in anonymous FTP, it is not recommended. If anonymous FTP must be used on a system, the requirement must be authorized and approved in the system accreditation package.'
  desc 'check', 'Attempt to log into this host with a user name of anonymous and a password of guest (also try the password of guest@mail.com). If the logon is successful and the use of anonymous ftp has not been documented and approved by the IAO, this is a finding.

Procedure:
# ftp localhost
Name: anonymous
530 Guest login not allowed on this machine.'
  desc 'fix', 'Configure the FTP service to not permit anonymous logins.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36185r1_chk'
  tag severity: 'medium'
  tag gid: 'V-846'
  tag rid: 'SV-37526r1_rule'
  tag stig_id: 'GEN004820'
  tag gtitle: 'GEN004820'
  tag fix_id: 'F-31440r1_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001475']
  tag nist: ['AC-22 c']
end
