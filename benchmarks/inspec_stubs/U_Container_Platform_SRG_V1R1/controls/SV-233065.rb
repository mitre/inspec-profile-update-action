control 'SV-233065' do
  title 'The container platform must verify container images.'
  desc 'The container platform must be capable of validating container images are signed and that the digital signature is from a recognized and approved source approved by the organization. Allowing any container image to be introduced into the registry and instantiated into a container can allow for services to be introduced that are not trusted and may contain malicious code, which introduces unwanted services. These unwanted services can cause harm and security risks to the hosting server, the container platform, other services running within the container platform, and the overall organization.'
  desc 'check', 'Review the container platform configuration to determine if container images are verified by enforcing image signing and that the image is signed recognized by an approved source. 

If container images are not verified or the signature is not verified as a recognized and approved source, this is a finding.'
  desc 'fix', 'Configure the container platform to verify container images are digitally signed and the signature is from a recognized and approved source.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36001r599552_chk'
  tag severity: 'medium'
  tag gid: 'V-233065'
  tag rid: 'SV-233065r599553_rule'
  tag stig_id: 'SRG-APP-000131-CTR-000285'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-35969r598832_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
