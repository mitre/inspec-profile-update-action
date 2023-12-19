control 'SV-45969' do
  title 'The snmpd.conf file must not have an extended ACL.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'check', "Check the permissions of the SNMP configuration file.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 

# ls -lL <snmpd.conf>

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <snmpd.conf file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43250r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22452'
  tag rid: 'SV-45969r1_rule'
  tag stig_id: 'GEN005375'
  tag gtitle: 'GEN005375'
  tag fix_id: 'F-39334r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
