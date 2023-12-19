control 'SV-237324' do
  title 'The ArcGIS Server must protect audit information from any type of unauthorized read access, modification or deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', 'Review the ArcGIS Server configuration to ensure mechanisms are provided that protect audit information from any type of unauthorized read access, modification or deletion. Substitute the target environment’s values for [bracketed] variables. 

Within Windows Explorer, access the "Security" (tab) property of the "[C:\\arcgisserver]\\logs" folder.

Verify only the "ArcGIS Server Account" has full control of this folder. Verify any other accounts that have read or other rights to this folder are authorized and documented.

If unauthorized accounts have read or other rights to this folder, this is a finding.'
  desc 'fix', 'Configure the ArcGIS Server to ensure mechanisms are provided that protect audit information from any type of unauthorized read access, modification or deletion. Substitute the target environment’s values for [bracketed] variables. 

Within Windows Explorer, access the "Security" (tab) property of the "[C:\\arcgisserver]\\logs" folder. Grant the "ArcGIS Server Account" full control of this folder.

Remove any unauthorized accounts or groups from this folder.'
  impact 0.5
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40543r642789_chk'
  tag severity: 'medium'
  tag gid: 'V-237324'
  tag rid: 'SV-237324r879576_rule'
  tag stig_id: 'AGIS-00-000044'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-40506r642790_fix'
  tag satisfies: ['SRG-APP-000118', 'SRG-APP-000119', 'SRG-APP-000120']
  tag 'documentable'
  tag legacy: ['SV-79897', 'V-65407']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
