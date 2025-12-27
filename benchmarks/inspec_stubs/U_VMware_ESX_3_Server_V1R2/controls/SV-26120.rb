control 'SV-26120' do
  title 'The snmpd.conf file must be group-owned by root, bin, sys, or system.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not group-owned by a system group, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Determine the group owner of the snmpd.conf file (or equivalent).

Procedure:
# ls -lL <snmpd.conf file>

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the snmpd.conf file (or equivalent).

Procedure:
# chgrp root <snmpd.conf>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29270r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22451'
  tag rid: 'SV-26120r1_rule'
  tag stig_id: 'GEN005365'
  tag gtitle: 'GEN005365'
  tag fix_id: 'F-26296r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
