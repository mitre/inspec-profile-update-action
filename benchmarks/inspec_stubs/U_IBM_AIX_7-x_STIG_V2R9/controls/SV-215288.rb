control 'SV-215288' do
  title 'All AIX shells referenced in passwd file must be listed in /etc/shells file, except any shells specified for the purpose of preventing logins.'
  desc 'The /etc/shells file lists approved default shells. It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized unsecure shell.'
  desc 'check', %q(Confirm the login shells referenced in the "/etc/passwd" file are listed in the "/etc/security/login.cfg" file's "shells =variable" in the usw stanza by running commands: 

#  more /etc/security/login.cfg | grep shells | grep -v '*'
        shells = /bin/sh,/bin/bsh,/bin/csh,/bin/ksh,/bin/tsh,/bin/ksh93,/usr/bin/sh,/usr/bin/bsh,/usr/bin/csh,/usr/bin/ksh,/usr/bin/tsh 

# more /etc/shells 
/bin/csh
/bin/ksh
/bin/psh
/bin/tsh
/bin/bsh
/usr/bin/csh
/usr/bin/ksh
/usr/bin/psh
/usr/bin/tsh
/usr/bin/bsh

The "/usr/bin/false", "/bin/false", "/dev/null", "/sbin/nologin" (and equivalents), and "sdshell" will be considered valid shells for use in the "/etc/passwd" file, but will not be listed in the shells stanza. 
If a shell referenced in "/etc/passwd" is not listed in the shells stanza, excluding the above mentioned shells, this is a finding.)
  desc 'fix', 'Use the "chsh" utility or edit the "/etc/passwd" file and correct the error by changing the default shell of the account in error to an acceptable shell name contained in the "/etc/shells file". 

Alternatively, use the SMIT to change the "/etc/passwd" shell entry.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16486r294315_chk'
  tag severity: 'medium'
  tag gid: 'V-215288'
  tag rid: 'SV-215288r508663_rule'
  tag stig_id: 'AIX7-00-002103'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16484r294316_fix'
  tag 'documentable'
  tag legacy: ['SV-101739', 'V-91641']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
