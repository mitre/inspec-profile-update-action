control 'SV-233164' do
  title 'The container platform must audit the execution of privileged functions.'
  desc 'Privileged functions within the container platform can be component specific or can envelope the entire container platform. Because of the nature of the commands, it is important to understand what command was executed for either investigation of an incident or for debugging/error correction; therefore, privileged function execution must be audited.'
  desc 'check', 'Review container platform documentation and log configuration to verify the application server logs privileged activity. 

If the container platform is not configured to log privileged activity, this is a finding.'
  desc 'fix', 'Configure the container platform to log privileged activity.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36100r599128_chk'
  tag severity: 'medium'
  tag gid: 'V-233164'
  tag rid: 'SV-233164r599509_rule'
  tag stig_id: 'SRG-APP-000343-CTR-000780'
  tag gtitle: 'SRG-APP-000343'
  tag fix_id: 'F-36068r599129_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
