control 'SV-51494' do
  title 'The test and development infrastructure must use a firewall for traffic inspection to and from DoD operational networks.'
  desc 'A firewall is necessary to inspect traffic as it flows into and out of the test and development environment.  Without a firewall present, traffic could flow freely between the operational network and test and development environment, allowing malicious or other unintended traffic and unauthorized access, compromising a system or environment.'
  desc 'check', 'Install and configure a firewall to separate DoD operational and test and development environments.'
  desc 'fix', 'Install and configure a firewall to separate DoD operational and test and development environments.'
  impact 0.7
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46802r2_chk'
  tag severity: 'high'
  tag gid: 'V-39636'
  tag rid: 'SV-51494r1_rule'
  tag stig_id: 'ENTD0180'
  tag gtitle: 'ENTD0180 - A firewall has not been installed to protect the test and development environment.'
  tag fix_id: 'F-44643r2_fix'
  tag 'documentable'
  tag ia_controls: 'DCSP-1, EBBD-1, EBBD-2, EBBD-3, ECSC-1'
end
