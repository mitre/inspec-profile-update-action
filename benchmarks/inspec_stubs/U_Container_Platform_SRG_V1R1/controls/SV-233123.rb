control 'SV-233123' do
  title 'The container platform must preserve any information necessary to determine the cause of the disruption or failure.'
  desc 'When a failure occurs within the container platform, preserving the state of the container platform and its components, along with other container services, helps to facilitate container platform restart and return to the operational mode of the organization with less disruption to mission essential processes. When preserving state, considerations for preservation of data confidentiality and integrity must be taken into consideration.'
  desc 'check', 'Review the container platform configuration to determine if information necessary to determine the cause of a disruption or failure is preserved. 

If the information is not preserved, this is a finding.'
  desc 'fix', 'Configure the container platform to preserve information necessary to determine the cause of the disruption or failure.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36059r599005_chk'
  tag severity: 'medium'
  tag gid: 'V-233123'
  tag rid: 'SV-233123r599509_rule'
  tag stig_id: 'SRG-APP-000226-CTR-000575'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-36027r599006_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
