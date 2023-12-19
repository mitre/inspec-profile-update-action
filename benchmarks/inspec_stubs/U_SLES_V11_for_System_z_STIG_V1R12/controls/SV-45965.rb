control 'SV-45965' do
  title 'The snmpd.conf file must be owned by root.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not owned by root, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Determine the owner of the SNMP configuration file.

Procedure:
Find the snmpd.conf file. The default install location is /etc/snmp/snmpd.conf but may be different depending on the SNMP agent installed.

# find / -name snmpd.conf 
# ls -lL <snmpd.conf>

If the snmpd.conf file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the snmpd.conf file to root.

Procedure:
# chown root <snmpd.conf file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12019'
  tag rid: 'SV-45965r1_rule'
  tag stig_id: 'GEN005360'
  tag gtitle: 'GEN005360'
  tag fix_id: 'F-39330r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
