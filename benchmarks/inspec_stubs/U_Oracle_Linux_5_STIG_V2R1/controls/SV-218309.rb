control 'SV-218309' do
  title 'User home directories must not have extended ACLs.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', "Verify user home directories have no extended ACLs.

# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld
 
If the permissions include a '+', the file has an extended ACL this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all [user home directory with extended ACL]'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19784r554264_chk'
  tag severity: 'low'
  tag gid: 'V-218309'
  tag rid: 'SV-218309r603259_rule'
  tag stig_id: 'GEN001490'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19782r554265_fix'
  tag 'documentable'
  tag legacy: ['V-22350', 'SV-64587']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
