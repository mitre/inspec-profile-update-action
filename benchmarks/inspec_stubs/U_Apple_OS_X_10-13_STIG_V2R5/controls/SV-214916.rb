control 'SV-214916' do
  title 'The macOS system must not process Internet Control Message Protocol [ICMP] timestamp requests.'
  desc 'ICMP timestamp requests reveal information about the system and can be used to determine which operating system is installed. Precise time data can also be used to launch time-based attacks against the system. Configuring the system to drop incoming ICMPv4 timestamp requests mitigates these risks.'
  desc 'check', 'To check if the system is configured to process ICMP timestamp requests, run the following command:

sysctl net.inet.icmp.timestamp

If the value is not set to "0", this is a finding.'
  desc 'fix', 'To disable ICMP timestamp responses, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.icmp.timestamp=0'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16116r397320_chk'
  tag severity: 'medium'
  tag gid: 'V-214916'
  tag rid: 'SV-214916r609363_rule'
  tag stig_id: 'AOSX-13-001220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16114r397321_fix'
  tag 'documentable'
  tag legacy: ['SV-96427', 'V-81713']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
