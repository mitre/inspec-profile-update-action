control 'SV-6991' do
  title 'Notices are not prominently displayed informing everyone of the ban of disguised jump drives.'
  desc 'Without a notice being posted, users could violate the ban and protest the seizer of the devices.'
  desc 'check', 'The reviewer will interview the IAO and view the notices.'
  desc 'fix', 'Post the required notices informing people entering a location containing DOD ISs that disguised USB jump drives are banned'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2918r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6769'
  tag rid: 'SV-6991r1_rule'
  tag stig_id: 'USB01.004.00'
  tag gtitle: 'USB Notice of Disguised Jump Drive Ban'
  tag fix_id: 'F-6422r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
