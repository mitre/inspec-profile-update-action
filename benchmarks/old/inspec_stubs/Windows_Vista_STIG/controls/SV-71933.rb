control 'SV-71933' do
  title 'The system must be configured to add all error reports to the queue.'
  desc 'Error reports are queued for sending to an error reporting site when the queueing behavior is set to Always Queue.  This will maintain the reports in the queue until a connection can be made to the collection server.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Queue" to "Enabled" with "Queuing behavior:" to "Always queue".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-57471'
  tag rid: 'SV-71933r1_rule'
  tag stig_id: 'WINER-000014'
  tag gtitle: 'WINER-000014'
  tag fix_id: 'F-62729r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
