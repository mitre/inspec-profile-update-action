control 'SV-6990' do
  title 'Disguised jump drives are not banned from locations containing DOD ISs.'
  desc 'Since they could easily be overlooked in a spot search to verify that no restricted or sensitive information is being removed from a location, disguised USB jump drives will be banned from locations containing DOD ISs.
The IAO, SA, and user will ensure disguised jump drives are not permitted in locations containing DoD ISs.'
  desc 'check', 'The reviewer will interview the IAO to verify that the policy banning disguised jump drives from locations containing DoD ISs is disseminated to all users.'
  desc 'fix', 'Disseminate the policy banning disguised jump drives from locations containing DoD ISs to all users.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2916r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6768'
  tag rid: 'SV-6990r1_rule'
  tag stig_id: 'USB01.003.00'
  tag gtitle: 'USB Disguised Jump Drives'
  tag fix_id: 'F-6421r1_fix'
  tag 'documentable'
  tag responsibility: ['Other', 'Information Assurance Officer', 'System Administrator']
end
