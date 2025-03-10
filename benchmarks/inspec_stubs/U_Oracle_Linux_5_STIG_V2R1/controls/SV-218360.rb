control 'SV-218360' do
  title 'Audio devices must have mode 0660 or less permissive.'
  desc "Audio and video devices that are globally accessible have proven to be another security hazard.  There is software that can activate system microphones and video devices connected to user workstations and/or X terminals.  Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it.  This action effectively changes the user's microphone into a bugging device."
  desc 'check', 'Check the mode of audio devices.
# ls -lL /dev/audio* /dev/snd/*
If the mode of audio devices are more permissive than 660, this is a finding.'
  desc 'fix', 'Change the mode of audio devices.
# chmod 0660 <audio device>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19835r569044_chk'
  tag severity: 'medium'
  tag gid: 'V-218360'
  tag rid: 'SV-218360r603259_rule'
  tag stig_id: 'GEN002320'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-19833r569045_fix'
  tag 'documentable'
  tag legacy: ['V-1048', 'SV-63247']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
