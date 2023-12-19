control 'SV-27251' do
  title 'Audio devices must be group-owned by root, sys, or bin.'
  desc 'Without privileged group owners, audio devices will be vulnerable to being used as eaves-dropping devices by malicious users or intruders to possibly listen to conversations containing sensitive information.'
  desc 'fix', 'Change the group owner of the audio device.

Procedure:
# chgrp system <audio device>'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-1061'
  tag rid: 'SV-27251r1_rule'
  tag stig_id: 'GEN002360'
  tag gtitle: 'GEN002360'
  tag fix_id: 'F-1215r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
