control 'SV-37569' do
  title 'Audio devices must not have extended ACLs.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', "Check the permissions of audio devices.
# ls -lL /dev/audio* /dev/snd/*
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [device file]'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36218r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22367'
  tag rid: 'SV-37569r1_rule'
  tag stig_id: 'GEN002330'
  tag gtitle: 'GEN002330'
  tag fix_id: 'F-31478r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
