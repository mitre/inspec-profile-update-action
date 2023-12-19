control 'SV-90835' do
  title 'The OS X system must not process Internet Control Message Protocol [ICMP] timestamp requests.'
  desc 'ICMP timestamp requests reveal information about the system and can be used to determine which operating system is installed. Precise time data can also be used to launch time-based attacks against the system. Configuring the system to drop incoming ICMPv4 timestamp requests mitigates these risks.'
  desc 'check', 'To check if the system is configured to process ICMP timestamp requests, run the following command:

sysctl net.inet.icmp.timestamp

If the value is not set to "0", this is a finding.'
  desc 'fix', 'To disable ICMP timestamp responses, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.icmp.timestamp=0'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76147'
  tag rid: 'SV-90835r1_rule'
  tag stig_id: 'AOSX-12-001220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82785r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
