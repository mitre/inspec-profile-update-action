control 'SV-38242' do
  title 'Audio devices must be owned by root.'
  desc "Globally accessible audio and video devices have proven to be another security hazard. There is software capable of activating system microphones and video devices connected to user workstations and/or X terminals. Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it. This action effectively changes the user's microphone into a bugging device."
  desc 'check', 'Check the owner of audio devices. Determine audio devices and class identifiers, i.e., audio should be listed as audio.
# ioscan

Determine audio device special files.
# ioscan -fn -C <audio class ID from the above command output>

Determine the device file mode.
# ls -lL <device special file>

If the owner of any audio device file is not root, this is a finding.'
  desc 'fix', 'Change the owner of the audio device.
# chown root <audio device>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36419r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1049'
  tag rid: 'SV-38242r1_rule'
  tag stig_id: 'GEN002340'
  tag gtitle: 'GEN002340'
  tag fix_id: 'F-31757r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
