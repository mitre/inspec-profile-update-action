control 'SV-240932' do
  title 'The vAMI must protect log information from unauthorized deletion.'
  desc 'If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow for unfettered access to those records. Application servers also write log data to log files that are stored on the OS, so appropriate file permissions must also be used to restrict access. Log information includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized deletion.'
  desc 'check', 'At the command prompt, execute the following command: 

ls -lL /opt/vmware/var/log/vami /opt/vmware/var/log/sfcb 

If log files are not owned by root, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chown root:root </path/to/file>

Note: Replace </path/to/file> with the file(s) that are not owned by root.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44165r675961_chk'
  tag severity: 'medium'
  tag gid: 'V-240932'
  tag rid: 'SV-240932r879578_rule'
  tag stig_id: 'VRAU-VA-000140'
  tag gtitle: 'SRG-APP-000120-AS-000080'
  tag fix_id: 'F-44124r675962_fix'
  tag 'documentable'
  tag legacy: ['SV-100857', 'V-90207']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
