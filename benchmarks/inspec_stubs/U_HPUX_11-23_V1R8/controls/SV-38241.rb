control 'SV-38241' do
  title 'Audio devices must have mode 0660 or less permissive.'
  desc "Globally accessible audio and video devices have proven to be another security hazard. There is software capable of activating system microphones and video devices connected to user workstations and/or X terminals. Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it. This action effectively changes the user's microphone into a bugging device."
  desc 'check', 'Check the mode of audio device files. Determine audio devices and class identifiers, i.e., audio should be listed as audio.
# ioscan

Determine audio device special files.
# ioscan -fn -C <audio class ID from the above command output>

Determine the device file mode.
# ls -lL <device special file>

If the mode of any audio device file is more permissive than 0660, this is a finding.'
  desc 'fix', 'Change the mode of audio devices.
# chmod 0660 <audio device>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36418r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1048'
  tag rid: 'SV-38241r1_rule'
  tag stig_id: 'GEN002320'
  tag gtitle: 'GEN002320'
  tag fix_id: 'F-31756r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
