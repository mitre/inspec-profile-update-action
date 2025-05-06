control 'SV-251672' do
  title 'Splunk Enterprise installation directories must be secured.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', 'This check must be done as the "splunk" user created during installation.

Verify owner and group are set to splunk user.

ls -ld $SPLUNK_HOME and $SPLUNK_ETC 

If the owner or group are not set to the splunk user, this is a finding.

Check for 700 as permission.

stat -c "%a %n" $SPLUNK_HOME and $SPLUNK_ETC 

If the permissions are not set to 700, this is a finding.'
  desc 'fix', 'Only the "splunk" and root users should have access to the Splunk Enterprise installation directories.

chown splunk user $SPLUNK_HOME and $SPLUNK_ETC
chgrp splunk user $SPLUNK_HOME and $SPLUNK_ETC
chmod 700 $SPLUNK_HOME and $SPLUNK_ETC'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55110r808250_chk'
  tag severity: 'medium'
  tag gid: 'V-251672'
  tag rid: 'SV-251672r879576_rule'
  tag stig_id: 'SPLK-CL-000190'
  tag gtitle: 'SRG-APP-000118-AU-000100'
  tag fix_id: 'F-55064r808251_fix'
  tag satisfies: ['SRG-APP-000118-AU-000100', 'SRG-APP-000119-AU-000110', 'SRG-APP-000120-AU-000120', 'SRG-APP-000121-AU-000130', 'SRG-APP-000122-AU-000140', 'SRG-APP-000123-AU-000150']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9', 'AU-9']
end
