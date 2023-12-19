control 'SV-38354' do
  title 'Audio devices must not have extended ACLs.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', 'Check the permissions of audio devices.
Determine audio devices and class identifiers, i.e., audio should be listed as audio.
# ioscan

Determine audio/video device special files.
# ioscan -fn -C <class ID from the above command output>

Determine the device file mode.
# ls -lL <device special file>

If the permissions include a "+" the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z [device file]'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36397r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22367'
  tag rid: 'SV-38354r1_rule'
  tag stig_id: 'GEN002330'
  tag gtitle: 'GEN002330'
  tag fix_id: 'F-31736r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
