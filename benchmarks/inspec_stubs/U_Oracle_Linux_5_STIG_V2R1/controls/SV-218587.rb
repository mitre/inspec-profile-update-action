control 'SV-218587' do
  title 'The snmpd.conf file must not have an extended ACL.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'check', "Check the permissions of the SNMP configuration file.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 

# ls -lL <snmpd.conf>

If the permissions include a '+', the file has an extended ACL. 

If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all <snmpd.conf file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20062r555959_chk'
  tag severity: 'medium'
  tag gid: 'V-218587'
  tag rid: 'SV-218587r603259_rule'
  tag stig_id: 'GEN005375'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20060r555960_fix'
  tag 'documentable'
  tag legacy: ['V-22452', 'SV-63463']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
