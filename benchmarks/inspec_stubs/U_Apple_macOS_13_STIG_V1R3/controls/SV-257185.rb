control 'SV-257185' do
  title 'The macOS system must be configured to disable SMB File Sharing unless it is required.'
  desc 'File sharing is usually nonessential and must be disabled if not required. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', 'Verify the macOS system is configured to disable the SMB File Sharing service with the following command:

/bin/launchctl print-disabled system | /usr/bin/grep com.apple.smbd

"com.apple.smbd" => disabled

If the results are not "com.apple.smbd => disabled" or SMB file sharing has not been documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the SMB File Sharing service with the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.smbd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60870r905186_chk'
  tag severity: 'medium'
  tag gid: 'V-257185'
  tag rid: 'SV-257185r905188_rule'
  tag stig_id: 'APPL-13-002001'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60811r905187_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
