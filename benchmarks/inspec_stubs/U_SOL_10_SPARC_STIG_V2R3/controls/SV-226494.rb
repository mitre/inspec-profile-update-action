control 'SV-226494' do
  title 'System log files must not have extended ACLs, except as needed to support authorized software.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value.  Authorized software may be given log file access through the use of extended ACLs when needed and configured to provide the least privileges required.'
  desc 'check', 'Verify all system log files have no extended ACLs.

Procedure: 
# ls -lL /var/adm 
If the permissions include a "+", the file has an extended ACL. If an extended ACL exists, verify with the SA if the ACL is required to support authorized software and provides the minimum necessary permissions. If an extended ACL exists that provides access beyond the needs of authorized software, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28655r482867_chk'
  tag severity: 'medium'
  tag gid: 'V-226494'
  tag rid: 'SV-226494r603265_rule'
  tag stig_id: 'GEN001270'
  tag gtitle: 'SRG-OS-000206'
  tag fix_id: 'F-28643r482868_fix'
  tag 'documentable'
  tag legacy: ['SV-26369', 'V-22315']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
