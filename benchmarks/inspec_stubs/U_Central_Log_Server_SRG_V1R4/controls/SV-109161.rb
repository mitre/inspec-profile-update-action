control 'SV-109161' do
  title 'The Central Log Server must protect audit information from any type of unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to protect audit information from any unauthorized read access.

If the Central Log Server is not configured to protect audit information from any unauthorized read access, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to protect audit information from unauthorized read access.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-100057'
  tag rid: 'SV-109161r1_rule'
  tag stig_id: 'SRG-APP-000118-AU-000100'
  tag gtitle: 'SRG-APP-000118-AU-000100'
  tag fix_id: 'F-105741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
