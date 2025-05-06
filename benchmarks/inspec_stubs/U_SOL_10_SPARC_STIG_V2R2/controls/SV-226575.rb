control 'SV-226575' do
  title 'Audio devices must have mode 0660 or less permissive.'
  desc "Globally accessible  audio and video devices have proven to be security hazards.  There is software that can activate system microphones and video devices connected to user workstations and/or X terminals.  Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it.  This action effectively changes the user's microphone to a bugging device."
  desc 'check', 'Check the mode of audio devices.
# ls -lL /dev/audio
If the mode of audio devices are more permissive than 0660, this is a finding.'
  desc 'fix', 'Change the mode of the audio device.
# chmod -R 0660 /dev/audio'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28736r483134_chk'
  tag severity: 'medium'
  tag gid: 'V-226575'
  tag rid: 'SV-226575r603265_rule'
  tag stig_id: 'GEN002320'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-28724r483135_fix'
  tag 'documentable'
  tag legacy: ['V-1048', 'SV-27241']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
