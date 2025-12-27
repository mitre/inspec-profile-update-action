control 'SV-9033' do
  title 'A controlled interface must have interconnections among DoD information systems operating between DoD and non-DoD systems or networks.'
  desc 'The configuration of an AD trust relationship is one of the steps used to allow users in one domain to access resources in another domain, forest, or Kerberos realm. When a trust is defined between a DoD organization and a non-DoD organization, the security posture of the two organizations might be significantly different. If the non-DoD organization maintained a less secure environment and that environment were compromised, the presence of the AD trust might allow the DoD environment to be compromised also.'
  desc 'check', '1. Refer to the list of identified trusts obtained in a previous check (V8530).

2. For each of the identified trusts, determine if the other trust party is a non-DoD entity. For example, if the fully qualified domain name of the other party does not end in “.mil”, the other party is probably not a DoD entity.

3. Review the local documentation approving the external network connection and documentation indicating explicit approval of the trust by the DAA.

4. The external network connection documentation is maintained by the IAO\\NSO for compliance with the Network Infrastructure STIG.

5. If any trust is defined with a non-DoD system and there is no documentation indicating approval of the external network connection and explicit DAA approval of the trust, then this is a finding.'
  desc 'fix', 'Obtain DAA approval and document external, forest, or realm trust relationship. Or obtain documentation of the network connection approval and explicit trust approval by the DAA.'
  impact 0.7
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-7699r1_chk'
  tag severity: 'high'
  tag gid: 'V-8536'
  tag rid: 'SV-9033r2_rule'
  tag stig_id: 'AD.0181'
  tag gtitle: 'Trust - Non-DoD'
  tag fix_id: 'F-28136r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECIC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
