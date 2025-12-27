control 'SV-35108' do
  title 'The anonymous FTP account must be configured to use chroot or a similarly isolated environment.'
  desc 'If an anonymous FTP account does not use a chroot or similarly isolated environment,  the system may be more vulnerable to exploits against the FTP service.  Such exploits could allow an attacker to gain shell access to the system and view, edit, or remove sensitive files.'
  desc 'check', %q(Is FTP installed?
# ls -lL /usr/lbin/ftpd
If ftpd is not installed, this is not a finding.

If ftpd is installed, determine if there is an anonymous ftp user configured in /etc/passwd.
# cat /etc/passwd | egrep -c "^ftp|^anonymous"

The /etc/passwd file, home directory entry for the anonymous FTP user should appear as the following example:
ftp:4rL2xXxDatENY:509:159::/home/ftp/./:/usr/bin/false

If there is an anonymous ftp user configured in /etc/passwd, determine if the ftp/anonymous user's home directory entry in the /etc/passwd file configured for chroot?
# cat /etc/passwd | egrep "^ftp|^anonymous" | cut -f 6,6 -d ":"

A dot (.) in field 6 of the FTP /etc/passwd file determines where the chroot will be performed. In the above example, the new root directory is /home/ftp. If an anonymous ftp user is found and the above command does not return an absolute path with a home directory of "dot" (see the above example), this is a finding.)
  desc 'fix', 'Using the HP-SMH, configure the anonymous FTP service to operate in a chroot environment.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36590r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4388'
  tag rid: 'SV-35108r1_rule'
  tag stig_id: 'GEN005020'
  tag gtitle: 'GEN005020'
  tag fix_id: 'F-31957r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
