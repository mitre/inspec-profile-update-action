control 'SV-218361' do
  title 'Audio devices must not have extended ACLs.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', "Check the permissions of audio devices.
# ls -lL /dev/audio* /dev/snd/*
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [device file]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19836r561809_chk'
  tag severity: 'medium'
  tag gid: 'V-218361'
  tag rid: 'SV-218361r603259_rule'
  tag stig_id: 'GEN002330'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-19834r561810_fix'
  tag 'documentable'
  tag legacy: ['V-22367', 'SV-63293']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
