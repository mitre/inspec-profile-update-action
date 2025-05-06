control 'SV-209566' do
  title 'The macOS system must be configured to disable SMB File Sharing unless it is required.'
  desc 'File Sharing is usually non-essential and must be disabled if not required. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', 'If SMB File Sharing is required, this is Not Applicable.

To check if the SMB File Sharing service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.smbd

If the results do not show the following, this is a finding:

"com.apple.smbd" => true'
  desc 'fix', 'To disable the SMB File Sharing service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.smbd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9817r282180_chk'
  tag severity: 'medium'
  tag gid: 'V-209566'
  tag rid: 'SV-209566r610285_rule'
  tag stig_id: 'AOSX-14-002001'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-9817r282181_fix'
  tag 'documentable'
  tag legacy: ['SV-105003', 'V-95865']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
