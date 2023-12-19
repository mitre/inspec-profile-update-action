control 'SV-206459' do
  title 'The Central Log Server system backups must be retained for a minimum of 5 years for SAMLI and a minimum of 7 days for non-SAMI on media capable of guaranteeing file integrity for the minimum applicable information retention period.'
  desc 'If backups are not properly processed, protected, and stored on appropriate media, recovery from a system failure or implementation of a contingency plan would not include the data necessary to fully recover in the time required to ensure continued mission support.'
  desc 'check', 'Review the SSP, backup media documentation, and system backup configuration.
Verify the Central Log Server system is backed up to media capable of guaranteeing file integrity for a minimum of five years.
If the Central Log Server does not retain backups for a minimum of five years for SAMI and a minimum of seven days for non-SAMI, this is a finding.

If the Central Log Server system backups are not stored on appropriate media capable of guaranteeing file integrity for a minimum of five years for systems retaining SAMI, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to retain backups of system information for a minimum of five years for SAMI and a minimum of seven days for non-SAMI.

Select backup media that guarantees file integrity for a minimum of five years for systems retaining SAMI.
Document the required retention period in the SSP.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6719r767005_chk'
  tag severity: 'low'
  tag gid: 'V-206459'
  tag rid: 'SV-206459r767007_rule'
  tag stig_id: 'SRG-APP-000125-AU-000310'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-6719r767006_fix'
  tag 'documentable'
  tag legacy: ['SV-95841', 'V-81127']
  tag cci: ['CCI-000167', 'CCI-001348']
  tag nist: ['AU-11', 'AU-9 (2)']
end
