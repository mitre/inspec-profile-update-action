control 'SV-87203' do
  title 'Wireless network adapters must be turned off when the system is connected to a wired network.'
  desc 'If a client device supports simultaneous use of wireless and wired connections, then this increases the probability that an adversary who can access the device using its wireless interface can then route traffic through the device’s wired interface to attack devices on the wired network or obtain sensitive DoD information.'
  desc 'check', 'This is NA for systems that do not have wireless network adapters.

Disabling of wired network adapters can be accomplished through various means.  Third-party software that manages this is the most reliable solution.  Some network adapters may have a configuration option to address this locally.  At minimum, the organization must have a policy that users turn off wireless network adapters when connected to a wired network.

If wireless network adapters are not turned off when the system is connected to a wired network, this is a finding.'
  desc 'fix', 'Configure systems to turn off wireless network adapters when systems are connected to wired networks.  If this is not possible, develop and implement a policy that users must turn off wireless network adapters when systems are connected to wired networks.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-72767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72573'
  tag rid: 'SV-87203r1_rule'
  tag stig_id: 'WIN00-000200'
  tag gtitle: 'WIN00-000200'
  tag fix_id: 'F-78973r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
