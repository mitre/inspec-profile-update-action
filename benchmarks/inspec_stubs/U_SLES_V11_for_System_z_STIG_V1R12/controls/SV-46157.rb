control 'SV-46157' do
  title 'The anonymous FTP account must be configured to use chroot or a similarly isolated environment.'
  desc 'If an anonymous FTP account does not use a chroot or similarly isolated environment,  the system may be more vulnerable to exploits against the FTP service.  Such exploits could allow an attacker to gain shell access to the system and view, edit, or remove sensitive files.'
  desc 'check', 'For vsftp:
The FTP anonymous user is, by default, chrooted to the ftp users home directory as defined in the /etc/passwd file. This is integral to the server and may not be disabled.'
  desc 'fix', 'There is no fix associated with this vulnerability.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43418r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4388'
  tag rid: 'SV-46157r1_rule'
  tag stig_id: 'GEN005020'
  tag gtitle: 'GEN005020'
  tag fix_id: 'F-39496r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
