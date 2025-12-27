control 'SV-226956' do
  title 'The anonymous FTP account must be configured to use chroot or a similarly isolated environment.'
  desc 'If an anonymous FTP account does not use a chroot or similarly isolated environment,  the system may be more vulnerable to exploits against the FTP service.  Such exploits could allow an attacker to gain shell access to the system and view, edit, or remove sensitive files.'
  desc 'check', "The default Solaris FTP daemon, in.ftpd, uses the ftp user's home directory as the chroot base for anonymous FTP.  If any files and directories within the ftp user's home directory are owned by any user other than root, or if any subdirectory other than pub has permissions more permissive than 0111, this is a finding."
  desc 'fix', 'Run the ftpconfig(1M) command to set up a chroot-ed environment for anonymous FTP with appropriate constraints.

# ftpconfig < anonymous FTP home directory>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29118r485195_chk'
  tag severity: 'medium'
  tag gid: 'V-226956'
  tag rid: 'SV-226956r603265_rule'
  tag stig_id: 'GEN005020'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29106r485196_fix'
  tag 'documentable'
  tag legacy: ['V-4388', 'SV-39838']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
