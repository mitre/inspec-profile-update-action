control 'SV-37577' do
  title 'Audio devices must be group-owned by root, sys, bin, or system.'
  desc 'Without privileged group owners, audio devices will be vulnerable to being used as eaves-dropping devices by malicious users or intruders to possibly listen to conversations containing sensitive information.'
  desc 'check', 'Check the group-owner of audio devices.

Procedure:
# ls -lL /dev/audio* /dev/snd/*

If the group-owner of an audio device is not root, sys, bin, system, or audio this is a finding.'
  desc 'fix', 'Change the group-owner of the audio device.

Procedure:
# chgrp <root, sys, bin, system, audio> <audio device>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36404r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1061'
  tag rid: 'SV-37577r2_rule'
  tag stig_id: 'GEN002360'
  tag gtitle: 'GEN002360'
  tag fix_id: 'F-31613r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
