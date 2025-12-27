control 'SV-233015' do
  title 'The container platform must use TLS 1.2 or greater for secure container image transport from trusted sources.'
  desc 'The authenticity and integrity of the container image during the container image lifecycle is part of the overall security posture of the container platform. This begins with the container image creation and pull of a base image from a trusted source for child container image creation and the instantiation of the new image into a running service. If an insecure protocol is used during transmission of container images at any step of the lifecycle, a bad actor may inject nefarious code into the container image. The container image, when instantiated, then becomes a security risk to the container platform, the host server, and other containers within the container platform. To thwart the injection of code during transmission, a secure protocol (TLS 1.2 or newer) must be used. Further guidance on secure transport protocols can be found in NIST SP 800-52.'
  desc 'check', 'Review the container platform configuration to verify that TLS 1.2 or greater is being used for secure container image transport from trusted sources. 

If TLS 1.2 or greater is not being used for secure container image transport, this is a finding.'
  desc 'fix', 'Configure the container platform to use TLS 1.2 or greater when components communicate internally or externally. The fix ensures that all communication components in the container platform are configured to utilize secure versions of TLS.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35951r598681_chk'
  tag severity: 'medium'
  tag gid: 'V-233015'
  tag rid: 'SV-233015r599509_rule'
  tag stig_id: 'SRG-APP-000014-CTR-000035'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-35919r598682_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
