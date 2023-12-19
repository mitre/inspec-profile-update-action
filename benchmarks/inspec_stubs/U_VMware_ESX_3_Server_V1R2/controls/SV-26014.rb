control 'SV-26014' do
  title 'Audio devices must not have extended ACLs.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', "Determine the audio device files for the system.
# ls -l <audio device file>
If the permissions include a '+', the file has an extended ACL, this is a finding."
  desc 'fix', 'Remove the extended ACL from the audio device file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29198r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22367'
  tag rid: 'SV-26014r1_rule'
  tag stig_id: 'GEN002330'
  tag gtitle: 'GEN002330'
  tag fix_id: 'F-26220r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
