control 'SV-27243' do
  title 'Audio devices must have mode 0660 or less permissive.'
  desc "Audio and video devices that are globally accessible have proven to be another security hazard.  There is software that can activate system microphones and video devices connected to user workstations and/or X terminals.  Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it.  This action effectively changes the user's microphone to a bugging device."
  desc 'check', 'Check the mode of audio devices.
# /usr/sbin/lsdev -C | grep -i audio 
#  ls -lL /dev/*aud0 
If the mode of audio devices are more permissive than 0660, this is a finding.'
  desc 'fix', 'Change the mode of audio devices.
# chmod o-w <audio device>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28267r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1048'
  tag rid: 'SV-27243r1_rule'
  tag stig_id: 'GEN002320'
  tag gtitle: 'GEN002320'
  tag fix_id: 'F-24491r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
