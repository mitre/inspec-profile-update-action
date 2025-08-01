control 'SV-251355' do
  title 'Prior to having external connection provisioned between enclaves, a Memorandum of Agreement (MOA) or Memorandum of Understanding (MOU) must be established.'
  desc 'Prior to establishing a connection with another activity, a Memorandum of Understanding (MOU) or Memorandum of Agreement (MOA) must be established between the two sites prior to connecting with each other.'
  desc 'check', "Review the network topology and interview the ISSO to verify that each external connection to the site's network has been validated and approved by the AO and CAO and that CAP requirements have been met.

If there are any external connections that have not been validated and approved, this is a finding."
  desc 'fix', 'All external connections will be validated and approved prior to connection. Interview the ISSM to verify that all connections have a mission requirement and that the AO is aware of the requirement.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54790r806018_chk'
  tag severity: 'medium'
  tag gid: 'V-251355'
  tag rid: 'SV-251355r806020_rule'
  tag stig_id: 'NET0131'
  tag gtitle: 'NET0131'
  tag fix_id: 'F-54743r806019_fix'
  tag 'documentable'
  tag legacy: ['V-66349', 'SV-80839']
  tag cci: ['CCI-001121']
  tag nist: ['SC-7 (14)']
end
