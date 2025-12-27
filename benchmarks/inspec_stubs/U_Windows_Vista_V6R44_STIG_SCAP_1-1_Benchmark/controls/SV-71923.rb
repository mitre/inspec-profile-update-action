control 'SV-71923' do
  title 'The system must be configured to queue error reports until a local or DOD-wide collector is available.'
  desc 'Queueing error reports provides the ability for a system to collect reports locally or until a collection server can be contacted.  Valuable system diagnostic and vulnerability information may be lost if the report queue is disabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Queue" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-57469'
  tag rid: 'SV-71923r1_rule'
  tag stig_id: 'WINER-000013'
  tag gtitle: 'WINER-000013'
  tag fix_id: 'F-62719r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
