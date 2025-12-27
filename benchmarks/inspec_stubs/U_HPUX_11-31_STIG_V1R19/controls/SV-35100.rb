control 'SV-35100' do
  title 'Anonymous FTP must not be active on the system unless authorized.'
  desc 'Due to the numerous vulnerabilities inherent in anonymous FTP, it is not recommended for use.  If anonymous FTP must be used on a system, the requirement must be authorized and approved in the system accreditation package.'
  desc 'check', "Attempt to log in with anonymous or ftp. The user can type any string of characters as a password. (By convention, the 
password is the host name of the user's host or the user's email address.)  The anonymous user is then given access only to user ftp's home directory, usually called /home/ftp.
 
If the login is successful, this is a finding."
  desc 'fix', 'Configure the FTP service to not permit anonymous logins. 
Remove the user(s) ftp and/or anonymous from the /etc/passwd file.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36580r2_chk'
  tag severity: 'medium'
  tag gid: 'V-846'
  tag rid: 'SV-35100r1_rule'
  tag stig_id: 'GEN004820'
  tag gtitle: 'GEN004820'
  tag fix_id: 'F-31948r2_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001475']
  tag nist: ['AC-22 c']
end
