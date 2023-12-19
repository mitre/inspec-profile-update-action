control 'SV-218447' do
  title 'The cron.deny file must not have an extended ACL.'
  desc 'If there are excessive file permissions for the cron.deny file, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', "Check the permissions of the file.

# ls -lL /etc/cron.deny

If the permissions include a '+', the file has an extended ACL. 

If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all /etc/cron.deny'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19922r562498_chk'
  tag severity: 'medium'
  tag gid: 'V-218447'
  tag rid: 'SV-218447r603259_rule'
  tag stig_id: 'GEN003210'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19920r562499_fix'
  tag 'documentable'
  tag legacy: ['V-22389', 'SV-64331']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
