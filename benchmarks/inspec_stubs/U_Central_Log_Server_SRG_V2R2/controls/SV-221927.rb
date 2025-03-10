control 'SV-221927' do
  title 'The Central Log Server must only allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates. 

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to only allow the use of DoD PKI certificate authorities.

If the Central Log Server is not configured to only allow DoD PKI certificate authorities, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to only allow the use of DoD PKI certificate authorities.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23642r420123_chk'
  tag severity: 'medium'
  tag gid: 'V-221927'
  tag rid: 'SV-221927r855324_rule'
  tag stig_id: 'SRG-APP-000427-AU-000040'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-23631r420124_fix'
  tag 'documentable'
  tag legacy: ['SV-109179', 'V-100075']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
