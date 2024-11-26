control 'SV-206511' do
  title 'The Central Log Server must be configured to off-load interconnected systems in real time and off-load standalone systems weekly, at a minimum.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. Although this may be part of the operating system function, for the enterprise events management system, this is most often a function managed through the application since it is a critical function and requires the use of a large amount of external storage.'
  desc 'check', 'Note: This is not applicable (NA) if an external application or operating system manages this function.

Examine the configuration.

Verify the system is configured to off-load interconnected systems in real time and off-load standalone systems weekly, at a minimum.

If the Central Log Server is not configured to off-load interconnected systems in real time and off-load standalone systems weekly, at a minimum, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to off-load interconnected systems in real time and off-load standalone systems weekly, at a minimum.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6771r285774_chk'
  tag severity: 'low'
  tag gid: 'V-206511'
  tag rid: 'SV-206511r400879_rule'
  tag stig_id: 'SRG-APP-000515-AU-000110'
  tag gtitle: 'SRG-APP-000515'
  tag fix_id: 'F-6771r285775_fix'
  tag 'documentable'
  tag legacy: ['SV-95891', 'V-81177']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
