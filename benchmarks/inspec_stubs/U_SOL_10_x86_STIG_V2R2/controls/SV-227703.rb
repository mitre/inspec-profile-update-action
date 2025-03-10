control 'SV-227703' do
  title 'Audio devices must be owned by root.'
  desc "Globally Accessible audio and video devices have proven to be security hazards.  There is software that can activate system microphones and video devices connected to user workstations and/or X terminals.  Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it.  This action effectively changes the user's microphone to a bugging device."
  desc 'check', 'Check the owner of audio devices.
# ls -lL /dev/audio
If the owner of any audio device file is not root, this is a finding.'
  desc 'fix', 'Change the owner of the audio device.
# chown root <audio device>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29865r488690_chk'
  tag severity: 'medium'
  tag gid: 'V-227703'
  tag rid: 'SV-227703r603266_rule'
  tag stig_id: 'GEN002340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29853r488691_fix'
  tag 'documentable'
  tag legacy: ['V-1049', 'SV-27246']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
