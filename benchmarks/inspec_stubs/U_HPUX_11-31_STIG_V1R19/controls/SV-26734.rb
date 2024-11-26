control 'SV-26734' do
  title 'The snmpd.conf file must be group-owned by root, sys, bin or other.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification. If the file is not group-owned by root or a system group, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Check the group ownership of the SNMP configuration file.
# ls -lL /etc/SnmpAgent.d/snmpd.conf

If the file is not group-owned by root, sys, bin or other, this is a finding.'
  desc 'fix', 'Change the group ownership of the SNMP configuration file.
# chgrp root /etc/SnmpAgent.d/snmpd.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36616r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22451'
  tag rid: 'SV-26734r1_rule'
  tag stig_id: 'GEN005365'
  tag gtitle: 'GEN005365'
  tag fix_id: 'F-31982r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
