control 'SV-986' do
  title 'Default system accounts (with the exception of root) must not be listed in the at.allow file or must be included in the at.deny file if the at.allow file does not exist.'
  desc 'Default accounts, such as bin, sys, adm, uucp, daemon, and others, should never have access to the "at" facility.  This would create a possible vulnerability open to intruders or malicious users.'
  desc 'check', 'Check the contents of the at.allow file.  If default accounts (such as bin, sys, adm, and others) are listed in the at.allow file, this is a finding.'
  desc 'fix', 'Remove the default accounts (such as bin, sys, adm, and others) from the at.allow file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28539r1_chk'
  tag severity: 'medium'
  tag gid: 'V-986'
  tag rid: 'SV-986r2_rule'
  tag stig_id: 'GEN003320'
  tag gtitle: 'GEN003320'
  tag fix_id: 'F-1140r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
