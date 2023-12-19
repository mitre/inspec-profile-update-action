control 'SV-35203' do
  title 'The snmpd.conf file must be owned by bin.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification. If the file is not owned by bin, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Determine the owner of the SNMP configuration file. 

# ls -lL /etc/SnmpAgent.d/snmpd.conf

If the snmpd.conf file is not owned by bin, this is a finding.'
  desc 'fix', 'Change the owner of the snmpd.conf file to bin.

# chown bin /etc/SnmpAgent.d/snmpd.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36615r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12019'
  tag rid: 'SV-35203r1_rule'
  tag stig_id: 'GEN005360'
  tag gtitle: 'GEN005360'
  tag fix_id: 'F-31981r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
