control 'SV-33015' do
  title 'Classified web servers will be afforded physical security commensurate with the classification of its content.'
  desc 'When data of a classified nature is migrated to a web server, fundamental principles applicable to the safeguarding of classified material must be followed. A classified web server needs to be afforded physical security commensurate with the classification of its content to ensure the protection of the data it houses.'
  desc 'check', 'The reviewer should query the ISSO, the SA, the web administrator, or developers as necessary to determine if a classified web server is afforded physical security commensurate with the classification of its content (i.e., is located in a vault or a room approved for classified storage at the highest classification processed on that system).

Ask what the classification of the web server is, and based on the classification, evaluate the location of the web server to determine if it is approved for storage of that classification level.

If the web server is not appropriately physically protected based on its classification, this is a finding.'
  desc 'fix', 'Relocate the web server to a location appropriate to classified devices.'
  impact 0.7
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33697r2_chk'
  tag severity: 'high'
  tag gid: 'V-13591'
  tag rid: 'SV-33015r2_rule'
  tag stig_id: 'WA155 W22'
  tag gtitle: 'WA155'
  tag fix_id: 'F-29321r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
