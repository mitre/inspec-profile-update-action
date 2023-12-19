control 'SV-215298' do
  title 'AIX must turn on SSH daemon reverse name checking.'
  desc 'If reverse name checking is off, SSH may allow a remote attacker to circumvent security policies and attempt to or actually login from IP addresses that are not permitted to access resources.'
  desc 'check', %q(Check the SSH daemon configuration for the "VerifyReverseMapping" setting using command: 

# grep -i VerifyReverseMapping  /etc/ssh/sshd_config | grep -v '^#' 
VerifyReverseMapping yes

If the setting is not present or the setting is "no", this is a finding.)
  desc 'fix', 'Edit the "/etc/sshd/sshd_config" file and add the following line:
VerifyReverseMapping yes

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16496r294345_chk'
  tag severity: 'medium'
  tag gid: 'V-215298'
  tag rid: 'SV-215298r508663_rule'
  tag stig_id: 'AIX7-00-002115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16494r294346_fix'
  tag 'documentable'
  tag legacy: ['V-91727', 'SV-101825']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
