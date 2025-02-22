control 'SV-233016' do
  title 'The container platform must use TLS 1.2 or greater for secure communication.'
  desc 'The authenticity and integrity of the container platform and communication between nodes and components must be secure. If an insecure protocol is used during transmission of data, the data can be intercepted and manipulated. The manipulation of data can be used to inject status changes of the container platform, causing the execution of containers or reporting an incorrect healthcheck. To thwart the manipulation of the data during transmission, a secure protocol (TLS 1.2 or newer) must be used. Further guidance on secure transport protocols can be found in NIST SP 800-52.'
  desc 'check', 'Review the container platform configuration to verify that TLS 1.2 or greater is being used for communication by the container platform nodes and components. 

If TLS 1.2 or greater is not being used for secure communication, this is a finding.'
  desc 'fix', 'Configure the container platform to use TLS 1.2 or greater for node and component communication.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35952r600535_chk'
  tag severity: 'medium'
  tag gid: 'V-233016'
  tag rid: 'SV-233016r879519_rule'
  tag stig_id: 'SRG-APP-000014-CTR-000040'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-35920r600536_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
