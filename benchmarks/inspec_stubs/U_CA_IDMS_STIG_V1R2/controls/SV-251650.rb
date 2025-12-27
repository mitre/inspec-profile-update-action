control 'SV-251650' do
  title 'Maintenance for security-related software updates for CA IDMS modules must be provided.'
  desc 'When a problem is found in IDMS, corrective maintenance is published to correct the problem (including security related problems). Published fixes should be applied to the IDMS system to correct any problems found.'
  desc 'check', 'Determining which PTFs have been applied, a query can be done to an SMP/E CSI using the IBM SMP/E utility.

New and existing PTFs must be reviewed using CA CARS or CSO in a timeframe determined by an authoritative source. If not, this is a finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that patches are consistently applied to the IDMS within the time allowed.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55085r807815_chk'
  tag severity: 'medium'
  tag gid: 'V-251650'
  tag rid: 'SV-251650r855289_rule'
  tag stig_id: 'IDMS-DB-000890'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-55039r807816_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
