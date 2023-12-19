control 'SV-218264' do
  title 'All network services daemon files must not have extended ACLs.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', "Check network services daemon files have no extended ACLs.

# ls -la /usr/sbin

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.

Note: Network daemons not residing in these directories must also be checked."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/sbin/*'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19739r568705_chk'
  tag severity: 'medium'
  tag gid: 'V-218264'
  tag rid: 'SV-218264r603259_rule'
  tag stig_id: 'GEN001190'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19737r568706_fix'
  tag 'documentable'
  tag legacy: ['V-22313', 'SV-64473']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
