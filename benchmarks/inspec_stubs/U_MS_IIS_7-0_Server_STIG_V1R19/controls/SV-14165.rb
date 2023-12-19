control 'SV-14165' do
  title 'Classified web servers will be afforded physical security commensurate with the classification of its content.'
  desc 'When data of a classified nature is migrated to a web server, fundamental principles applicable to the safeguarding of classified material must be followed. A classified web server needs to be afforded physical security commensurate with the classification of its content to ensure the protection of the data it houses.'
  desc 'check', 'Interview the ISSO, the SA, the web administrator, or developers as necessary to determine if a classified web server is afforded physical security commensurate with the classification of its content (i.e., is located in a vault or a room approved for classified storage at the highest classification processed on that system).

Ask what the classification of the web server is. Based on the classification, evaluate the location of the web server to determine if it is approved for storage of that classification level.

If there is a traditional reviewer available, work with him/her to address specific conditions or questions.

If the web server is not appropriately physically protected based on its classification, this is a finding.'
  desc 'fix', 'Relocate the web server to a location appropriate to classified devices.'
  impact 0.7
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-30035r2_chk'
  tag severity: 'high'
  tag gid: 'V-13591'
  tag rid: 'SV-14165r3_rule'
  tag stig_id: 'WA155'
  tag gtitle: 'WA155'
  tag fix_id: 'F-26869r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
