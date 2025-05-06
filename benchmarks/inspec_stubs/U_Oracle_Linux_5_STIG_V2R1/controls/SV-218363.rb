control 'SV-218363' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19838r561815_chk'
  tag severity: 'medium'
  tag gid: 'V-218363'
  tag rid: 'SV-218363r603259_rule'
  tag stig_id: 'GEN002360'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-19836r561816_fix'
  tag 'documentable'
  tag legacy: ['V-1061', 'SV-63341']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
