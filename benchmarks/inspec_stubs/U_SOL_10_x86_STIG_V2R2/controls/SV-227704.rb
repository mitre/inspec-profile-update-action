control 'SV-227704' do
  title 'Audio devices must be group-owned by root, sys, or bin.'
  desc 'Without privileged group owners, audio devices will be vulnerable to being used as eaves-dropping devices by malicious users or intruders to possibly listen to conversations containing sensitive information.'
  desc 'check', 'Check the group-owner of audio devices.

Procedure:
# ls -lL /dev/audio

If the group-owner of an audio device is not root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the group owner of the audio device.

Procedure:
# chgrp system <audio device>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29866r488693_chk'
  tag severity: 'medium'
  tag gid: 'V-227704'
  tag rid: 'SV-227704r603266_rule'
  tag stig_id: 'GEN002360'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29854r488694_fix'
  tag 'documentable'
  tag legacy: ['V-1061', 'SV-27251']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
