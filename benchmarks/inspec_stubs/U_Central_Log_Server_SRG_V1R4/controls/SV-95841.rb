control 'SV-95841' do
  title 'The Central Log Server system backups must be retained for a minimum of 5 years for SAML and a minimum of 7 days for on media capable of guaranteeing file integrity for a minimum of five years (SAML) and 7 days (non-SAML).'
  desc 'If backups are not properly processed, protected, and stored on appropriate media, recovery from a system failure or implementation of a contingency plan would not include the data necessary to fully recover in the time required to ensure continued mission support.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server system is backed up to media capable of guaranteeing file integrity for a minimum of five years.

If the Central Log Server system backups are not stored on appropriate media capable of guaranteeing file integrity for a minimum of five years, this is a finding.'
  desc 'fix', 'Configure the Central Log Server system to back up to media capable of guaranteeing file integrity for a minimum of five years.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80785r1_chk'
  tag severity: 'low'
  tag gid: 'V-81127'
  tag rid: 'SV-95841r2_rule'
  tag stig_id: 'SRG-APP-000125-AU-000310'
  tag gtitle: 'SRG-APP-000125-AU-000310'
  tag fix_id: 'F-87901r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000167', 'CCI-001348']
  tag nist: ['AU-11', 'AU-9 (2)']
end
