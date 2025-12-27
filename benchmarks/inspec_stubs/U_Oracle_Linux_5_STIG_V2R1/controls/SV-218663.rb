control 'SV-218663' do
  title 'The Network Information System (NIS) protocol must not be used.'
  desc 'Due to numerous security vulnerabilities existing within NIS, it must not be used.  Possible alternative directory services are NIS+ and LDAP.'
  desc 'check', 'Perform the following to determine if NIS is active on the system:

# ps -ef | grep ypbind

If NIS is found active on the system, this is a finding.'
  desc 'fix', 'Disable the use of NIS/NIS+. Use as a replacement Kerberos or LDAP.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20138r562909_chk'
  tag severity: 'medium'
  tag gid: 'V-218663'
  tag rid: 'SV-218663r603259_rule'
  tag stig_id: 'GEN006400'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20136r562910_fix'
  tag 'documentable'
  tag legacy: ['V-867', 'SV-63803']
  tag cci: ['CCI-001435', 'CCI-000381']
  tag nist: ['AC-17 (8)', 'CM-7 a']
end
