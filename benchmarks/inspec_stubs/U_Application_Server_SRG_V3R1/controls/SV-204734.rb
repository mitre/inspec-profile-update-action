control 'SV-204734' do
  title 'The application server must protect log information from unauthorized deletion.'
  desc 'If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. 

Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow for unfettered access to those records. Application servers also write log data to log files which are stored on the OS, so appropriate file permissions must also be used to restrict access.

Log information includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized deletion.'
  desc 'check', 'Review the configuration settings to determine if the application server log features protect log information from unauthorized deletion.

Review file system settings to verify the application server sets secure file permissions on log files to prevent unauthorized deletion.

If the application server does not protect log information from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the application server to protect log information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4854r282849_chk'
  tag severity: 'medium'
  tag gid: 'V-204734'
  tag rid: 'SV-204734r508029_rule'
  tag stig_id: 'SRG-APP-000120-AS-000080'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-4854r282850_fix'
  tag 'documentable'
  tag legacy: ['V-35212', 'SV-46499']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
