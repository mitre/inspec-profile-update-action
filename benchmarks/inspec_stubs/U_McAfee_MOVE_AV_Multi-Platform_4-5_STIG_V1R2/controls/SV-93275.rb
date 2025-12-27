control 'SV-93275' do
  title 'The McAfee MOVE AV SVM must be configured with a static Internet Protocol (IP) address.'
  desc 'Security management devices must be configured to ensure consistent and uninterrupted connectivity to/from the systems they manage/control. Otherwise, the security management device will be less than effective.'
  desc 'check', 'Access the server designated as the McAfee MOVE SVM.

Access Network properties. 

From listed Network adapters, right-click on the active adapter and select "Properties". 

Highlight "Internet Protocol Version 4 (TCP/IPv4)" and click on the "Properties" button. 

On the "General" tab, ensure "Use the following IP address:" is selected and the "IP address:", "Subnet mask:", and "Default gateway:" are all populated. 

If the IPv4 protocol has not been configured to use a static IP address, subnet mask, and default gateway, this is a finding.'
  desc 'fix', 'In accordance with local operational procedures, assign a static IP address to the server designated as the McAfee MOVE SVM.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78139r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78569'
  tag rid: 'SV-93275r1_rule'
  tag stig_id: 'MV45-SVM-000004'
  tag gtitle: 'MV45-SVM-000004'
  tag fix_id: 'F-85305r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
