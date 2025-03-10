control 'SV-27253' do
  title 'Audio devices must be group-owned by root, sys, bin, or system.'
  desc 'Without privileged group owners, audio devices will be vulnerable to being used as eaves-dropping devices by malicious users or intruders to possibly listen to conversations containing sensitive information.'
  desc 'check', 'Check the group owner of audio devices.

Procedure:
# /usr/sbin/lsdev -C | grep -i audio 
# ls -lL /dev/*aud0 

If the group owner of an audio device is not root, sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the audio device.

Procedure:
# chgrp system <audio device>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28285r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1061'
  tag rid: 'SV-27253r1_rule'
  tag stig_id: 'GEN002360'
  tag gtitle: 'GEN002360'
  tag fix_id: 'F-1215r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
