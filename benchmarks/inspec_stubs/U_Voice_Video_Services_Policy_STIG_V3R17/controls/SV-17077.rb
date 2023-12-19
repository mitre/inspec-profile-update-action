control 'SV-17077' do
  title 'Deficient training or training materials addressing secure PC communications client application usage.'
  desc 'Users of PC based voice, video, UC, and collaboration communications applications must be aware of, and trained in, the various aspects of the application’s safe and proper use. They must also be aware of the application or service vulnerabilities and the mitigations for them. This awareness is supported by a combination of user training in the use of the application and any associated accessories as well as its limitations and vulnerabilities. Training is subsequently acknowledged through the signing of user agreements and bolstered by the distribution and utilization of user guides.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure training materials are developed and PC based voice, video, UC, and collaboration communications application users are trained in, and aware of, various aspects of the application’s safe and proper use as well as the application or service vulnerabilities. Training will include all items contained in user agreements and user guides.

Ask the IAO about the training provided to users about the various aspects of the application’s safe and proper use as well as the application or service vulnerabilities. Inspect training materials for the content contained in user agreements. 

This is a finding if the training materials do not address the contents of the user agreements and the various aspects of the application’s safe and proper use as well as the application or service vulnerabilities.'
  desc 'fix', 'Ensure training materials are developed and PC based voice, video, UC, and collaboration communications application users are trained in, and aware of, various aspects of the application’s safe and proper use as well as the application or service vulnerabilities. Training will include all items contained in user agreements and user guides.

Develop training materials that address the contents of the user agreements and the various aspects of the application’s safe and proper use as well as the application or service vulnerabilities'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17132r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16089'
  tag rid: 'SV-17077r1_rule'
  tag stig_id: 'VVoIP 1305 (GENERAL)'
  tag gtitle: 'Deficient User Trng: PC Comm App Secure Use'
  tag fix_id: 'F-16194r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent and/or improper disclosure of sensitive or classified information.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
