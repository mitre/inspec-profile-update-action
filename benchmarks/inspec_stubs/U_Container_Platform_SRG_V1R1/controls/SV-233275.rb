control 'SV-233275' do
  title 'The container platform must continuously scan components, containers, and images for vulnerabilities.'
  desc 'Finding vulnerabilities quickly within the container platform and within containers deployed within the platform is important to keep the overall platform secure. When a vulnerability within a component or container is unknown or allowed to remain unpatched, other containers and customers within the platform become vulnerability. The vulnerability can lead to the loss of application data, organizational infrastructure data, and denial of service (DoS) to hosted applications.

Vulnerability scanning can be performed by the container platform or by external applications.'
  desc 'check', 'Review the container platform to validate continuous vulnerability scans of components, containers, and container images are being performed. 

If continuous vulnerability scans are not being performed, this is a finding.'
  desc 'fix', 'Implement continuous vulnerability scans of container platform components, containers, and container images either by the container platform or from external vulnerability scanning applications.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36211r599461_chk'
  tag severity: 'medium'
  tag gid: 'V-233275'
  tag rid: 'SV-233275r599509_rule'
  tag stig_id: 'SRG-APP-000516-CTR-001335'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36179r599462_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
