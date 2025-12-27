control 'SV-205477' do
  title 'The Mainframe Product must protect audit information from any type of unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Examine installation and configuration settings.

Verify the Mainframe Product restricts audit information read access to system programmers, security administrators, and audit personnel.

If access is not restricted, this is a finding.

If an external security manager (ESM) is being used, examine external security configuration and rules.

If the rules do not restrict read access to system programmers, security managers, and audit personnel, this is a finding.'
  desc 'fix', 'Verify the Mainframe Product restricts read access to system programmers, security administrators, and audit personnel.

This can be accomplished using an ESM.

Configure the Mainframe Product to provide a SAF call for audit information access.

Verify ESM rules restrict read access to system programmers, security administrators, and audit personnel.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5743r299664_chk'
  tag severity: 'medium'
  tag gid: 'V-205477'
  tag rid: 'SV-205477r539590_rule'
  tag stig_id: 'SRG-APP-000118-MFP-000174'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-5743r539589_fix'
  tag 'documentable'
  tag legacy: ['SV-82781', 'V-68291']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
