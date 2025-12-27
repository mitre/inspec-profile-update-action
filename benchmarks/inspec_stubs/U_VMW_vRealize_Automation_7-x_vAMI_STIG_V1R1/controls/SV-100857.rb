control 'SV-100857' do
  title 'The vAMI must protect log information from unauthorized deletion.'
  desc 'If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow for unfettered access to those records. Application servers also write log data to log files that are stored on the OS, so appropriate file permissions must also be used to restrict access. Log information includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized deletion.'
  desc 'check', 'At the command prompt, execute the following command: 

ls -lL /opt/vmware/var/log/vami /opt/vmware/var/log/sfcb 

If log files are not owned by root, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chown root:root </path/to/file>

Note: Replace </path/to/file> with the file(s) that are not owned by root.'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90207'
  tag rid: 'SV-100857r1_rule'
  tag stig_id: 'VRAU-VA-000140'
  tag gtitle: 'SRG-APP-000120-AS-000080'
  tag fix_id: 'F-96949r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
