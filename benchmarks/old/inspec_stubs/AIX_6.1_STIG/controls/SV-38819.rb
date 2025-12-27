control 'SV-38819' do
  title 'The snmpd.conf file must not have an extended ACL.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'check', 'Determine if the snmpd.conf file or equivalent has an extended ACL.

Procedure:

# find / -name "snmpd*.conf"
# aclget < snmpd conf >
If the extended attributes are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the snmpd.conf file (or equivalent) and change extended attributes to disabled.

#acledit < snmpd conf >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37063r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22452'
  tag rid: 'SV-38819r1_rule'
  tag stig_id: 'GEN005375'
  tag gtitle: 'GEN005375'
  tag fix_id: 'F-32329r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
