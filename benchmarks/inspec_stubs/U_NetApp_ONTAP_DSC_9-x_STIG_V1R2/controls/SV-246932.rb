control 'SV-246932' do
  title 'ONTAP must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', 'Use "security login banner show" to see the current login notice and consent banner.

If ONTAP is not configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device, this is a finding.'
  desc 'fix', 'Configure the Standard Mandatory DoD Notice and Consent Banner with "security login banner modify -message <Standard DoD Notice and Consent Banner>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50364r835217_chk'
  tag severity: 'medium'
  tag gid: 'V-246932'
  tag rid: 'SV-246932r835218_rule'
  tag stig_id: 'NAOT-AC-000011'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-50318r769127_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
