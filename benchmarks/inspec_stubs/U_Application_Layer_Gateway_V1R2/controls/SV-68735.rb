control 'SV-68735' do
  title 'The ALG that is part of a CDS must enforce information flow control based on organization-defined metadata.'
  desc 'Enforcing allowed information flows based on metadata enables simpler and more effective flow control. Metadata is information used to describe the characteristics of data. Metadata can include structural metadata describing data structures (e.g., data format, syntax, and semantics) or descriptive metadata describing data contents (e.g., age, location, telephone number).

Information flow control regulates where information is allowed to travel within a network and between hosts, as opposed to who is allowed to access the information. Information flow enforcement mechanisms, such as cross domain solutions, compare metadata attached to the data and respond appropriately (e.g., allow, block, quarantine, or alert administrator).

Organization-defined metadata used for flow control in CDS systems depend on the environment, data, and security boundaries. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify that policy filters exist that enforce traffic flow inbound and outbound across the controlled security boundary based on organization-defined metadata.

If the ALG does not control traffic based on organization-defined metadata, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure inbound or outbound policy filters to enforce traffic flow across the controlled security boundary based on organization-defined metadata.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54489'
  tag rid: 'SV-68735r1_rule'
  tag stig_id: 'SRG-NET-000280-ALG-000080'
  tag gtitle: 'SRG-NET-000280-ALG-000080'
  tag fix_id: 'F-59343r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000030', 'CCI-000366']
  tag nist: ['AC-4 (6)', 'CM-6 b']
end
