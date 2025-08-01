control 'SV-226862' do
  title 'Default system accounts (with the exception of root) must not be listed in the at.allow file or must be included in the at.deny file if the at.allow file does not exist.'
  desc 'Default accounts, such as bin, sys, adm, uucp, daemon, and others, should never have access to the at facility.  This would create a possible vulnerability open to intruders or malicious users.'
  desc 'check', '# more /etc/cron.d/at.allow
If default accounts (such as bin, sys, adm, and others) are listed in the at.allow file, this is a finding.'
  desc 'fix', 'Remove the default accounts (such as bin, sys, adm, and others) from the at.allow file.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29024r484870_chk'
  tag severity: 'medium'
  tag gid: 'V-226862'
  tag rid: 'SV-226862r603265_rule'
  tag stig_id: 'GEN003320'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29012r484871_fix'
  tag 'documentable'
  tag legacy: ['SV-27384', 'V-986']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
