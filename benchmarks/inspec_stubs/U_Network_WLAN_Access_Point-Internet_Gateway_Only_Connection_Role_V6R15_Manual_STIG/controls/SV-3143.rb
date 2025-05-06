control 'SV-3143' do
  title 'Network devices must not have any default manufacturer passwords.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password thus gaining access to the device and causing network outage or denial of service. Many default vendor passwords are well-known; hence, not removing them prior to deploying the network devices into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Review the network devices configuration to determine if the vendor default password is active.

If any vendor default passwords are used on the device, this is a finding.'
  desc 'fix', 'Remove any vendor default passwords from the network devices configuration.'
  impact 0.7
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-40236r3_chk'
  tag severity: 'high'
  tag gid: 'V-3143'
  tag rid: 'SV-3143r4_rule'
  tag stig_id: 'NET0240'
  tag gtitle: 'Devices exist with standard default passwords.'
  tag fix_id: 'F-35391r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
