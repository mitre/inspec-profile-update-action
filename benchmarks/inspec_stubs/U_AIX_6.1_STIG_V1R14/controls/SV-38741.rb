control 'SV-38741' do
  title 'The /etc/shells (or equivalent) file must exist.'
  desc 'The shells file (or equivalent) lists approved default shells.  It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized shell that may not be secure.'
  desc 'check', 'Check /etc/security/login.cfg for a shells stanza.
Procedure:
# grep -p usw: /etc/security/login.cfg | grep "shells ="
If no such stanza exists, this is a finding.

Check the /etc/shells file.
Procedure:
# more /etc/shells
If the /etc/shells file does not exist,  this is a finding.'
  desc 'fix', 'Edit the /etc/security/login.cfg file and add a shells stanza containing a list of valid shells.
#chsec -f /etc/security/login.cfg -s usw -a shells=<list of approved shells>

Create the /etc/shells file.
#vi /etc/shells'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37242r1_chk'
  tag severity: 'medium'
  tag gid: 'V-916'
  tag rid: 'SV-38741r1_rule'
  tag stig_id: 'GEN002120'
  tag gtitle: 'GEN002120'
  tag fix_id: 'F-32456r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
