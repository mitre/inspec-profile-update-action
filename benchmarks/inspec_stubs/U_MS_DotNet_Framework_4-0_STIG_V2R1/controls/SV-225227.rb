control 'SV-225227' do
  title 'CAS and policy configuration files must be backed up.'
  desc 'A successful disaster recovery plan requires that CAS policy and CAS policy configuration files are identified and included in systems disaster backup and recovery events.  Documentation regarding the location of system and application specific CAS policy configuration files and the frequency in which backups occur is required.  If these files are not identified and the information is not documented, there is the potential that critical application configuration files may not be included in disaster recovery events which could lead to an availability risk.'
  desc 'check', 'Ask the System Administrator if all CAS policy and policy configuration files are included in the system backup. If they are not, this is a finding.

Ask the System Administrator if the policy and configuration files are backed up prior to migration, deployment, and reconfiguration. If they are not, this is a finding.

Ask the System Administrator for documentation that shows CAS Policy configuration files are backed up as part of a disaster recovery plan. If they have no documentation proving the files are backed up, this is a finding.'
  desc 'fix', 'All CAS policy and policy configuration files must be included in the system backup. 

All CAS policy and policy configuration files must be backed up prior to migration, deployment, and reconfiguration.

CAS policy configuration files must be included in disaster recovery plan documentation.'
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26926r467996_chk'
  tag severity: 'medium'
  tag gid: 'V-225227'
  tag rid: 'SV-225227r615940_rule'
  tag stig_id: 'APPNET0055'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-26914r467997_fix'
  tag 'documentable'
  tag legacy: ['SV-7452', 'V-7069']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
