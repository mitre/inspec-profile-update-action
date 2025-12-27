control 'SV-226567' do
  title 'All shells referenced in /etc/passwd must be listed in the /etc/shells file, except any shells specified for the purpose of preventing logins.'
  desc 'The shells file lists approved default shells.  It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized shell that may not be secure.'
  desc 'check', 'Confirm the login shells referenced in the /etc/passwd file are listed in the /etc/shells file.  

Procedure:
# more /etc/passwd
# more /etc/shells

The /usr/bin/false, /bin/false, /dev/null, /sbin/nologin, (and equivalents), and sdshell will be considered valid shells for use in the /etc/passwd file, but will not be listed in the /etc/shells file.

If a shell referenced in /etc/passwd is not listed in the shells file, excluding the above mentioned shells, this is a finding.'
  desc 'fix', 'Use the chsh utility or edit the /etc/passwd file and correct the error by changing the default shell of the account in error to an acceptable shell name contained in the /etc/shells file.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28728r483110_chk'
  tag severity: 'medium'
  tag gid: 'V-226567'
  tag rid: 'SV-226567r603265_rule'
  tag stig_id: 'GEN002140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28716r483111_fix'
  tag 'documentable'
  tag legacy: ['V-917', 'SV-917']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
