control 'SV-215416' do
  title 'All global initialization file executable search paths must contain only absolute paths.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', %q(Check the global initialization files' executable search paths using: 

# grep -i PATH /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login /etc/security/environ 
/etc/environment:PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/java7_64/jre/bin:/usr/java7_64/bin
/etc/environment:LOCPATH=/usr/lib/nls/loc
/etc/environment:NLSPATH=/usr/lib/nls/msg/%L/%N:/usr/lib/nls/msg/%L/%N.cat:/usr/lib/nls/msg/%l.%c/%N:/usr/lib/nls/msg/%l.%c/%N.cat

This variable is formatted as a colon-separated list of directories. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/) or other than "$PATH", it is a relative path, and this is a finding.)
  desc 'fix', 'Edit the global initialization file(s) with "PATH" variables containing relative paths. Edit the file and remove the relative path from the PATH variable.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16614r294699_chk'
  tag severity: 'medium'
  tag gid: 'V-215416'
  tag rid: 'SV-215416r508663_rule'
  tag stig_id: 'AIX7-00-003120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16612r294700_fix'
  tag 'documentable'
  tag legacy: ['V-91669', 'SV-101767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
