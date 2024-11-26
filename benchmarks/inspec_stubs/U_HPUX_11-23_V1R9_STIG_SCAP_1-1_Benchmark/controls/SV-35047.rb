control 'SV-35047' do
  title 'Sendmail logging must not be set to less than 9 in the sendmail.cf file.'
  desc 'If Sendmail is not configured to log at level 9, system logs may not contain the information necessary for tracking unauthorized use of the sendmail service.'
  desc 'fix', 'Edit the sendmail.cf file, locate the  entry (and where 
necessary uncomment it and/or create it) and modify/set it to 9.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-835'
  tag rid: 'SV-35047r1_rule'
  tag stig_id: 'GEN004440'
  tag gtitle: 'GEN004440'
  tag fix_id: 'F-31932r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-3, ECAR-2, ECAR-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
