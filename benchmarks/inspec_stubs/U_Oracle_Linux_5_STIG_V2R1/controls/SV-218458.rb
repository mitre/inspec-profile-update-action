control 'SV-218458' do
  title 'Default system accounts (with the exception of root) must not be listed in the at.allow file or must be included in the at.deny file if the at.allow file does not exist.'
  desc 'Default accounts, such as bin, sys, adm, uucp, daemon, and others, should never have access to the "at" facility.  This would create a possible vulnerability open to intruders or malicious users.'
  desc 'check', '# more /etc/at.allow
If default accounts (such as bin, sys, adm, and others) are listed in the at.allow file, this is a finding.'
  desc 'fix', 'Remove the default accounts (such as bin, sys, adm, and others, traditionally UID less than 500) from the at.allow file.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19933r562531_chk'
  tag severity: 'medium'
  tag gid: 'V-218458'
  tag rid: 'SV-218458r603259_rule'
  tag stig_id: 'GEN003320'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19931r562532_fix'
  tag 'documentable'
  tag legacy: ['V-986', 'SV-64379']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
