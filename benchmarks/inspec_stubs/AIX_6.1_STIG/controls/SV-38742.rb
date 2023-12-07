control 'SV-38742' do
  title 'All shells referenced in /etc/passwd must be listed in the /etc/shells file, except any shells specified for the purpose of preventing logins.'
  desc 'The shells file lists approved default shells.  It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized shell that may not be secure.'
  desc 'check', "Confirm the login shells referenced in the /etc/passwd file are listed in the /etc/security/login.cfg file's shells =variable in the usw stanza.

# more /etc/security/login.cfg 
# more /etc/shells

The /usr/bin/false, /bin/false, /dev/null, /sbin/nologin, (and equivalents), and sdshell will be considered valid shells for use in the /etc/passwd file, but will not be listed in the shells stanza. If a shell referenced in /etc/passwd is not listed in the shells stanza, excluding the above mentioned shells, then this is a finding."
  desc 'fix', 'Use the chsh utility or edit the /etc/passwd file and correct the error by changing the default shell of the account in error to an acceptable shell name contained in the /etc/shells file. 

Alternatively, use the SMIT  to change the /etc/passwd shell entry.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37177r1_chk'
  tag severity: 'medium'
  tag gid: 'V-917'
  tag rid: 'SV-38742r1_rule'
  tag stig_id: 'GEN002140'
  tag gtitle: 'GEN002140'
  tag fix_id: 'F-32457r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
