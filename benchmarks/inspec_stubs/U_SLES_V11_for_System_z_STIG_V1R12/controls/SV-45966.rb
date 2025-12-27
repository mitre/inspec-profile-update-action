control 'SV-45966' do
  title 'The snmpd.conf file must be group-owned by root, bin, sys, or system.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not group-owned by a system group, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Check the group ownership of the SNMP configuration file.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 

# ls -lL <snmpd.conf>

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the SNMP configuration file.

Procedure:
# chgrp root <snmpd.conf>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43248r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22451'
  tag rid: 'SV-45966r1_rule'
  tag stig_id: 'GEN005365'
  tag gtitle: 'GEN005365'
  tag fix_id: 'F-39331r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
