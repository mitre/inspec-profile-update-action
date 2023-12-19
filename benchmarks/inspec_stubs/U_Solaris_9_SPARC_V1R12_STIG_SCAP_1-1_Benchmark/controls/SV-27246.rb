control 'SV-27246' do
  title 'Audio devices must be owned by root.'
  desc "Globally Accessible audio and video devices have proven to be security hazards.  There is software that can activate system microphones and video devices connected to user workstations and/or X terminals.  Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it.  This action effectively changes the user's microphone to a bugging device."
  desc 'fix', 'Change the owner of the audio device.
# chown root <audio device>'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-1049'
  tag rid: 'SV-27246r1_rule'
  tag stig_id: 'GEN002340'
  tag gtitle: 'GEN002340'
  tag fix_id: 'F-1203r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
