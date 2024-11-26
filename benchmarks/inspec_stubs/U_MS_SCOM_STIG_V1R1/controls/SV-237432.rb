control 'SV-237432' do
  title 'The Microsoft SCOM server must be running Windows operating system that supports modern security features such as virtualization based security.'
  desc 'Network devices running older but supported operating systems lack modern security features that mitigate attack surfaces. Attackers face a higher level of complexity to overcome during a compromise attempt.'
  desc 'check', 'Check the operating system version.

From the SCOM management servers, type winver and press enter. If the operating system is not Windows Server 2016 or later, this is a finding.'
  desc 'fix', 'Upgrade the network device to an operating that supports modern security features such as virtualization based security.'
  impact 0.7
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40651r663057_chk'
  tag severity: 'high'
  tag gid: 'V-237432'
  tag rid: 'SV-237432r643942_rule'
  tag stig_id: 'SCOM-CM-000001'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-40614r643941_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
