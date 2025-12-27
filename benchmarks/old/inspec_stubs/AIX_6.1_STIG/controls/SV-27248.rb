control 'SV-27248' do
  title 'Audio devices must be owned by root.'
  desc "Audio and video devices that are globally accessible have proven to be another security hazard.  There is software that can activate system microphones and video devices connected to user workstations and/or X terminals.  Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it.  This action effectively changes the user's microphone to a bugging device."
  desc 'check', 'Check the owner of audio devices.
Procedure:
# /usr/sbin/lsdev -C | grep -i audio 
#  ls -lL /dev/*aud0 
If the owner of any audio device file is not root, this is a finding.'
  desc 'fix', 'Change the owner of the audio device.
# chown root <audio device>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1049'
  tag rid: 'SV-27248r1_rule'
  tag stig_id: 'GEN002340'
  tag gtitle: 'GEN002340'
  tag fix_id: 'F-1203r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
