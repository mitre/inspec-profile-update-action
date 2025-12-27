control 'SV-26507' do
  title 'System audit tool executables must be group-owned by root, bin, sys, or system.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'fix', 'Change the group-owner of the audit tool executable to root, bin, sys, or system.

Procedure:
# chgrp root <audit tool executable>'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-22371'
  tag rid: 'SV-26507r1_rule'
  tag stig_id: 'GEN002716'
  tag gtitle: 'GEN002716'
  tag fix_id: 'F-23743r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
