control 'SV-246842' do
  title 'The HYCU server must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.'
  desc 'check', 'HYCU is a VM that synchronizes time with the Nutanix or VMware platform as part of maintenance task using the "chronyd" daemon.

To verify the service is up and running, execute the following command:
systemctl status chronyd

If service is not active (running), this is a finding.'
  desc 'fix', 'Verify time synchronization by logging on to the HYCU console and executing the following command:
sudo systemctl start chronyd

Additional assistance can be found at: https://support.hycu.com/hc/en-us/articles/115005424345-HYCU-system-time'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50274r768188_chk'
  tag severity: 'medium'
  tag gid: 'V-246842'
  tag rid: 'SV-246842r768190_rule'
  tag stig_id: 'HYCU-AU-000019'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-50228r768189_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
