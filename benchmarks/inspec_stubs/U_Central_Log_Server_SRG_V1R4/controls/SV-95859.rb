control 'SV-95859' do
  title 'The Central Log Server must be configured to off-load log records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. Although this may be part of the operating system function, for the enterprise events management system, this is most often a function managed through the application since it is a critical function and requires the use of a large amount of external storage.'
  desc 'check', 'Note: This is not applicable (NA) if an external application or operating system manages this function.

Examine the configuration.

Verify the system is configured to off-load log records onto a different system or media than the system being audited.

If the Central Log Server is not configured to off-load log records onto a different system or media than the system being audited, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to off-load log records onto a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80807r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81145'
  tag rid: 'SV-95859r1_rule'
  tag stig_id: 'SRG-APP-000358-AU-000100'
  tag gtitle: 'SRG-APP-000358-AU-000100'
  tag fix_id: 'F-87921r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
