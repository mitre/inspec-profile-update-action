control 'SV-206491' do
  title 'The Central Log Server must be configured to off-load log records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. Although this may be part of the operating system function, for the enterprise events management system, this is most often a function managed through the application since it is a critical function and requires the use of a large amount of external storage.'
  desc 'check', 'Note: This is not applicable (NA) if an external application or operating system manages this function.

Examine the configuration.

Verify the system is configured to off-load log records onto a different system or media than the system being audited.

If the Central Log Server is not configured to off-load log records onto a different system or media than the system being audited, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to off-load log records onto a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6751r285714_chk'
  tag severity: 'medium'
  tag gid: 'V-206491'
  tag rid: 'SV-206491r855298_rule'
  tag stig_id: 'SRG-APP-000358-AU-000100'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-6751r285715_fix'
  tag 'documentable'
  tag legacy: ['SV-95859', 'V-81145']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
