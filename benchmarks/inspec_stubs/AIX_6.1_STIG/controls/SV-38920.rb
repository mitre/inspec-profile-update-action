control 'SV-38920' do
  title 'The snmpd.conf file must be owned by root.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not owned by root, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Determine the owner of the SNMP configuration file. Consult vendor documentation to determine the location and name of the file. 

Procedure:
# find / -name "snmpd*.conf"
# ls -lL <snmpd.conf>

If the snmpd.conf file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the snmpd.conf file to bin.

Procedure:
# chown bin <snmpd.conf file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37060r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12019'
  tag rid: 'SV-38920r1_rule'
  tag stig_id: 'GEN005360'
  tag gtitle: 'GEN005360'
  tag fix_id: 'F-11278r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
