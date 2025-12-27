control 'SV-95987' do
  title 'The WebSphere Application Server sample applications must be removed.'
  desc 'WebSphere samples are not intended for use in a production environment. Do not run them there, as they create significant security risks. In particular, the snoop servlet can provide an outsider with tremendous amounts of information about your system. This is precisely the type of information you do not want to give a potential intruder. 

Do not install the samples during the profile creation or uninstall the sample programs.'
  desc 'check', 'Navigate to Applications >> All Applications.

Review all applications installed on the application server.

If the sample applications snoop, ivt, or DefaultApplication are installed on a production system, this is a finding.'
  desc 'fix', 'Navigate to Applications >> All Applications.

Click on the corresponding application checkbox.

Select "Remove".

Click "OK".

Click "Save".'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80971r1_chk'
  tag severity: 'low'
  tag gid: 'V-81273'
  tag rid: 'SV-95987r1_rule'
  tag stig_id: 'WBSP-AS-000930'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-88053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
