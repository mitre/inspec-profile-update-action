control 'SV-218362' do
  title 'Audio devices must be owned by root.'
  desc "Audio and video devices globally accessible have proven to be another security hazard. There is software that can activate system microphones and video devices connected to user workstations and/or X terminals. Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it. This action effectively changes the user's microphone into a bugging device."
  desc 'check', 'Check the owner of audio devices.
# ls -lL /dev/audio* /dev/snd/*
If the owner of any audio device file is not root, this is a finding.'
  desc 'fix', 'Edit the /etc/security/console.perms.d/50-default.perms file and comment the following line:

<console>  0600 <sound>  0660 root.audio'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19837r569047_chk'
  tag severity: 'medium'
  tag gid: 'V-218362'
  tag rid: 'SV-218362r603259_rule'
  tag stig_id: 'GEN002340'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-19835r569048_fix'
  tag 'documentable'
  tag legacy: ['V-1049', 'SV-63301']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
