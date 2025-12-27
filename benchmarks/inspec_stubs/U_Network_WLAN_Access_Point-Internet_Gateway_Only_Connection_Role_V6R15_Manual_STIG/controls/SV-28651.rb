control 'SV-28651' do
  title 'Network devices must use at least two NTP servers to synchronize time.'
  desc 'Without synchronized time, accurately correlating information between devices becomes difficult, if not impossible. If logs cannot be successfully compared between each of the routers, switches, and firewalls, it will be very difficult to determine the exact events that resulted in a network breach incident. NTP provides an efficient and scalable method for network devices to synchronize to an accurate time source.'
  desc 'check', 'Review the configuration and verify two NTP servers have been defined.

If the device is not configured to use two separate NTP servers, this is a finding.'
  desc 'fix', 'Configure the device to use two separate NTP servers.'
  impact 0.3
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-3581r5_chk'
  tag severity: 'low'
  tag gid: 'V-23747'
  tag rid: 'SV-28651r4_rule'
  tag stig_id: 'NET0812'
  tag gtitle: 'Two NTP servers are not used to synchronize time.'
  tag fix_id: 'F-3044r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
