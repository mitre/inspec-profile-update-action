control 'SV-6792' do
  title 'The manufacturer’s default passwords have not been changed for all SAN management software.'
  desc "The changing of passwords from the default value blocks malicious users with knowledge of the default passwords for the manufacturer's SAN Management software from creating a denial of service by disrupting the SAN or reconfigure the SAN topology leading to a compromise of sensitive data.
The IAO/NSO will ensure that the manufacturer’s default passwords are changed for all SAN management software."
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that the manufacturer’s default passwords have been changed for all SAN management software.'
  desc 'fix', 'Develop a plan to change manufacturer’s default passwords for all SAN management software.  Obtain CM approval of the plan and implement the plan.'
  impact 0.7
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2572r1_chk'
  tag severity: 'high'
  tag gid: 'V-6646'
  tag rid: 'SV-6792r1_rule'
  tag stig_id: 'SAN04.018.00'
  tag gtitle: 'Default SAN Management Software Password'
  tag fix_id: 'F-6249r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
