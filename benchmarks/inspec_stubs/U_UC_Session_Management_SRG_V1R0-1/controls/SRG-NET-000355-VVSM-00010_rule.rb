control 'SRG-NET-000355-VVSM-00010_rule' do
  title 'The Unified Communications Session Manager must only allow the use of DOD-approved PKI certificate authorities when using PKI.'
  desc 'Untrusted certificate authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

The DOD will only accept PKI certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates. 

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to any network element that is an intermediary of individual sessions (e.g., proxy, ALG, or TLS VPN). Network elements that perform these functions must be able to identify which session identifiers were generated when the sessions were established.'
  desc 'check', 'Verify the Unified Communications Session Manager, when using PKI, only uses DOD approved certificate authorities.

If the Unified Communications Session Manager, when using PKI, does not use DOD approved certificate authorities, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to only use DOD approved certificate authorities when using PKI.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000355-VVSM-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000355-VVSM-00010'
  tag rid: 'SRG-NET-000355-VVSM-00010_rule'
  tag stig_id: 'SRG-NET-000355-VVSM-00010'
  tag gtitle: 'SRG-NET-000355-VVSM-00010'
  tag fix_id: 'F-SRG-NET-000355-VVSM-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
