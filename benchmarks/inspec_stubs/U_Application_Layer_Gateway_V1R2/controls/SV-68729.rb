control 'SV-68729' do
  title 'The ALG that is part of a CDS must bind security attributes to information using organization-defined binding techniques to facilitate information flow policy enforcement.'
  desc 'If security attributes are not associated with the information being transmitted between systems, then access control policies and information flows which depend on these security attributes will not function and may also result in the unauthorized release (spillage) of information.

Binding techniques implemented by information systems affect the strength of security attribute binding to information. Binding strength and the assurance associated with binding techniques play an important part in the trust organizations have in the information flow enforcement process. The binding techniques affect the number and degree of additional reviews required by organizations.

Examples of strong bindings are digital signatures and other cryptographic techniques.

Organization-defined binding techniques for binding security attributes to associated information depend on the environment, data, and security boundaries of the specific CDS. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG binds security attributes to information using organization-defined binding techniques to facilitate information flow policy enforcement.

If the ALG does not bind security attributes to information using organization-defined binding techniques to facilitate information flow policy enforcement, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to bind security attributes to information using organization-defined binding techniques to facilitate information flow policy enforcement.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55099r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54483'
  tag rid: 'SV-68729r1_rule'
  tag stig_id: 'SRG-NET-000327-ALG-000077'
  tag gtitle: 'SRG-NET-000327-ALG-000077'
  tag fix_id: 'F-59337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002210']
  tag nist: ['CM-6 b', 'AC-4 (18)']
end
