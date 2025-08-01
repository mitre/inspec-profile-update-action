control 'SV-240931' do
  title 'The vAMI must protect log information from unauthorized modification.'
  desc 'If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to his or her advantage. Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow unfettered access to those records. Application servers also write log data to log files that are stored on the OS, so appropriate file permissions must also be used to restrict access. Log information includes all information (e.g., log records, log settings, transaction logs and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized modification.'
  desc 'check', 'At the command prompt, execute the following command: 

ls -lL /opt/vmware/var/log/vami /opt/vmware/var/log/sfcb 

If any log files are world-writable, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chmod 640 </path/to/file>

Note: Replace </path/to/file> with the file(s) with world-write rights.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44164r675958_chk'
  tag severity: 'medium'
  tag gid: 'V-240931'
  tag rid: 'SV-240931r879577_rule'
  tag stig_id: 'VRAU-VA-000135'
  tag gtitle: 'SRG-APP-000119-AS-000079'
  tag fix_id: 'F-44123r675959_fix'
  tag 'documentable'
  tag legacy: ['SV-100855', 'V-90205']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
