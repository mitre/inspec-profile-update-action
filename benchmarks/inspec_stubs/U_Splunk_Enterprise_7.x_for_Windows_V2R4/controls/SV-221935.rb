control 'SV-221935' do
  title 'Splunk Enterprise installation directories must be secured.'
  desc 'If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods, which will depend on system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', 'This check must be done as a server administrator.

From an Explorer window, right-click on the Splunk target installation folder and select Properties.

Select the Security tab and then the Advanced button.

Verify that Administrators and SYSTEM are the only accounts listed and are set to Full Control.

If accounts other than Administrators and SYSTEM are listed, this is a finding.'
  desc 'fix', 'This fix must be done as a server administrator.

From an Explorer window, right-click on the Splunk target installation folder and select Properties.

Select the Security tab >> Advanced >> Disable inheritance >> Convert inherited permissions into explicit permissions on this object.

Remove all permission entries except Administrators and SYSTEM, and select OK.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23649r420273_chk'
  tag severity: 'medium'
  tag gid: 'V-221935'
  tag rid: 'SV-221935r879576_rule'
  tag stig_id: 'SPLK-CL-000100'
  tag gtitle: 'SRG-APP-000118-AU-000100'
  tag fix_id: 'F-23638r420274_fix'
  tag satisfies: ['SRG-APP-000118-AU-000100', 'SRG-APP-000119-AU-000110', 'SRG-APP-000120-AU-000120', 'SRG-APP-000121-AU-000130', 'SRG-APP-000122-AU-000140', 'SRG-APP-000123-AU-000150']
  tag 'documentable'
  tag legacy: ['SV-111383', 'V-102437']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9', 'AU-9']
end
