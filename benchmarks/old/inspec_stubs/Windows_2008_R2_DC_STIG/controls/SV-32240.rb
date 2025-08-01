control 'SV-32240' do
  title 'The Automated Information System (AIS) will be physically secured in an access controlled area.'
  desc 'Inadequate physical protection can undermine all other security precautions utilized to protect the system. This can jeopardize the confidentiality, availability, and integrity of the system.  Physical security of the AIS is the first line protection of any system.'
  desc 'check', 'Interview the SA to determine if equipment is located in an access controlled area. 

Servers will be located in rooms, or locked cabinets, that are accessible only to authorized systems personnel. Authorized user access should be verified at two points (i.e. building access and server room).'
  desc 'fix', 'Relocate equipment to a controlled access area.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32862r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1070'
  tag rid: 'SV-32240r1_rule'
  tag gtitle: 'Physical security'
  tag fix_id: 'F-31r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
