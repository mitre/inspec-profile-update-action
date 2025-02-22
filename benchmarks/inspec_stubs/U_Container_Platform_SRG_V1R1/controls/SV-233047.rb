control 'SV-233047' do
  title 'All audit records must identify any users associated with the event within the container platform.'
  desc 'Without information that establishes the identity of the user associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Review container platform documentation and the log files on the application server to determine if the logs contain information that establishes the identity of the user or process associated with log event data. 

If the container platform does not produce logs that establish the identity of the user or process associated with log event data, this is a finding.'
  desc 'fix', 'Configure the container platform logging system to log the identity of the user or process related to the events.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35983r599538_chk'
  tag severity: 'medium'
  tag gid: 'V-233047'
  tag rid: 'SV-233047r599539_rule'
  tag stig_id: 'SRG-APP-000100-CTR-000195'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-35951r598778_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
