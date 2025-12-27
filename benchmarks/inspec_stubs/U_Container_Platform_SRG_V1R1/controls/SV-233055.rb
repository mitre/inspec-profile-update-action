control 'SV-233055' do
  title 'The container platform must use internal system clocks to generate audit record time stamps.'
  desc 'Understanding when and sequence of events for an incident is crucial to understand what may have taken place. Without a common clock, the components generating audit events could be out of synchronization and would then present a picture of the event that is warped and corrupted. To give a clear picture, it is important that the container platform and its components use a common internal clock.'
  desc 'check', 'Review the container platform configuration files to determine if the internal system clock is used for time stamps. 

If the container platform does not use the internal system clock to generate time stamps, this is a finding.'
  desc 'fix', 'Configure the container platform to use internal system clocks to generate time stamps for log records.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35991r598801_chk'
  tag severity: 'medium'
  tag gid: 'V-233055'
  tag rid: 'SV-233055r599509_rule'
  tag stig_id: 'SRG-APP-000116-CTR-000235'
  tag gtitle: 'SRG-APP-000116'
  tag fix_id: 'F-35959r598802_fix'
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
