control 'SV-38921' do
  title 'The snmpd.conf file must be group-owned by bin, sys, or system.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not group-owned by a system group, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Determine the group owner of the SNMP configuration files.

Procedure:
# ls -lL /etc/snmpd.conf /etc/snmpdv3.conf

If the file is not group owned by bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the SNMP configuration files.

Procedure:
# chgrp system /etc/snmpd.conf
# chgrp system /etc/snmpdv3.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37062r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22451'
  tag rid: 'SV-38921r1_rule'
  tag stig_id: 'GEN005365'
  tag gtitle: 'GEN005365'
  tag fix_id: 'F-33455r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
