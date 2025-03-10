control 'SV-29706' do
  title 'Internet Information System (IIS) or its subcomponents are installed on a workstation.'
  desc 'This is a Category 1 finding because not removing these services may allow unauthorized internet services to be hosted.  Web sites should only be hosted on servers that have been designed for that purpose and can be adequately secured.'
  desc 'fix', 'Configure the system to remove “Internet Information Services”.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-3347'
  tag rid: 'SV-29706r1_rule'
  tag gtitle: 'Internet Information System (IIS)'
  tag fix_id: 'F-5826r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
