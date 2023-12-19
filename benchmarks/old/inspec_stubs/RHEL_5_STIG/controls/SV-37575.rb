control 'SV-37575' do
  title 'Audio devices must be owned by root.'
  desc "Audio and video devices globally accessible have proven to be another security hazard. There is software that can activate system microphones and video devices connected to user workstations and/or X terminals. Once the microphone has been activated, it is possible to eavesdrop on otherwise private conversations without the victim being aware of it. This action effectively changes the user's microphone into a bugging device."
  desc 'fix', 'Edit the /etc/security/console.perms.d/50-default.perms file and comment the following line:

<console> 0600 <sound> 0660 root.audio'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-1049'
  tag rid: 'SV-37575r2_rule'
  tag stig_id: 'GEN002340'
  tag gtitle: 'GEN002340'
  tag fix_id: 'F-31611r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
