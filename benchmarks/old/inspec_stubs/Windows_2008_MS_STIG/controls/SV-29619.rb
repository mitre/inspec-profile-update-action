control 'SV-29619' do
  title 'Physical security of the Automated Information System (AIS) does not meet DISA requirements.'
  desc 'Inadequate physical protection can undermine all other security precautions utilized to protect the system. This can jeopardize the confidentiality, availability, and integrity of the system.  Physical security of the AIS is the first line protection of any system.'
  desc 'check', 'Interview the SA to determine if equipment is located in an access controlled area.
 
Note:  Servers will be located in rooms, or locked cabinets, that are accessible only to authorized systems personnel.  Authorized user access should be verified at two points (i.e. building access and server room).  User workstations containing sensitive data should be in access controlled areas.'
  desc 'fix', 'Relocate equipment to a controlled access area.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-7883r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1070'
  tag rid: 'SV-29619r1_rule'
  tag gtitle: 'Physical security'
  tag fix_id: 'F-31r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
