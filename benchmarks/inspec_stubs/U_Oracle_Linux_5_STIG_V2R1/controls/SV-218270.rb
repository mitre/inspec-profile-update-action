control 'SV-218270' do
  title 'System log files must not have extended ACLs, except as needed to support authorized software.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value.  Authorized software may be given log file access through the use of extended ACLs when needed and configured to provide the least privileges required.'
  desc 'check', "Verify system log files have no extended ACLs.

Procedure:
# ls -lL /var/log

If the permissions include a '+', the file has an extended ACL. If an extended ACL exists, verify with the SA if the ACL is required to support authorized software and provides the minimum necessary permissions. 

If an extended ACL exists, providing access beyond the needs of authorized software, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

Procedure:
# setfacl --remove-all [file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19745r568714_chk'
  tag severity: 'medium'
  tag gid: 'V-218270'
  tag rid: 'SV-218270r603259_rule'
  tag stig_id: 'GEN001270'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-19743r568715_fix'
  tag 'documentable'
  tag legacy: ['V-22315', 'SV-64493']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
