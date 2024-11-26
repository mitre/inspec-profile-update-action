control 'SV-246839' do
  title 'The HYCU server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'To ensure network devices have a sufficient storage capacity in which to write the audit logs, they must be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it can be modified.'
  desc 'check', 'Log on to the HYCU VM console. 

To verify audit logs size is restricted, check for the value of the "max_log_file_action" option in "/etc/audit/auditd.conf" with the following command:
sudo grep max_log_file_action /etc/audit/auditd.conf

If the "max_log_file_action" value is not set to "ROTATION", this is a finding.'
  desc 'fix', 'Configure the operating system to enforce log rotation and restrict log file size to an organization-defined value by editing "/etc/audit/auditd.conf" files using the following command:
sudo vi /etc/audit/auditd.conf

Add or modify the following lines to have the required value:
max_log_file_action = ROTATION
max_log_file = 6'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50271r768179_chk'
  tag severity: 'medium'
  tag gid: 'V-246839'
  tag rid: 'SV-246839r768181_rule'
  tag stig_id: 'HYCU-AU-000016'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-50225r768180_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
