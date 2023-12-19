control 'SV-215271' do
  title 'AIX audio devices must be group-owned by root, sys, bin, or system.'
  desc 'Without privileged group owners, audio devices will be vulnerable to being used as eaves-dropping devices by malicious users or intruders to possibly listen to conversations containing sensitive information.'
  desc 'check', 'Check the group owner of audio devices using commands:

# /usr/sbin/lsdev -C | grep -i audio 
aud0   Available             USB Audio Device

# ls -lL /dev/*aud0
cr--r--r--    1 root     system       16,  0 Jan 24 07:25 aud0 

If the group owner of an audio device is not "root", "sys", "bin", or "system", this is a finding.'
  desc 'fix', 'Change the group owner of the audio device using command: 
# chgrp system <audio device>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16469r294264_chk'
  tag severity: 'medium'
  tag gid: 'V-215271'
  tag rid: 'SV-215271r508663_rule'
  tag stig_id: 'AIX7-00-002079'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16467r294265_fix'
  tag 'documentable'
  tag legacy: ['SV-101695', 'V-91597']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
