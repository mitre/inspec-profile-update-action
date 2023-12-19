control 'SV-218266' do
  title 'All system command files must not have extended ACLs.'
  desc "Restricting permissions will protect system command files from unauthorized modification.  System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'check', "Check all system command files have no extended ACLs.
# ls -lL /etc /bin /usr/bin /usr/lbin /usr/usb /sbin /usr/sbin
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19741r568711_chk'
  tag severity: 'medium'
  tag gid: 'V-218266'
  tag rid: 'SV-218266r603259_rule'
  tag stig_id: 'GEN001210'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19739r568712_fix'
  tag 'documentable'
  tag legacy: ['V-22314', 'SV-64479']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
