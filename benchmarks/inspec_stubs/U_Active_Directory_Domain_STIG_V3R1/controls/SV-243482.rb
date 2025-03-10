control 'SV-243482' do
  title 'Interconnections between DoD directory services of different classification levels must use a cross-domain solution that is approved for use with inter-classification trusts.'
  desc 'If a robust cross-domain solution is not used, then it could permit unauthorized access to classified data. To support secure access between resources of different classification levels, the solution must meet discretionary access control requirements. There are currently, no DOD- approved solutions. 

Further Policy Details: Do not define trust relationships between domains, forests, or realms with resources at different classification levels. The configuration of a trust relationship is one of the steps used to allow users in one AD domain to access resources in another domain, forest, or Kerberos realm. (This check does not apply to trusts with non-DoD organizations since these trusts are examined in a previous check.)'
  desc 'check', '1. Refer to the list of identified trusts and the trust documentation provided by the site representative. (Obtained in V-8530)

2. For each of the identified trusts between DoD organizations, compare the classification level (unclassified, confidential, secret, and top secret) of the domain being reviewed with the classification level of the other trust party as noted in the documentation.

3. If the classification level of the domain being reviewed is different than the classification level of any of the entities for which a trust relationship is defined, then this is a finding.'
  desc 'fix', 'Delete the trust relationship that is defined between entities with resources at different DoD classification levels.'
  impact 0.7
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46757r723479_chk'
  tag severity: 'high'
  tag gid: 'V-243482'
  tag rid: 'SV-243482r723481_rule'
  tag stig_id: 'AD.0180'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46714r723480_fix'
  tag 'documentable'
  tag legacy: ['V-8534', 'SV-9031']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
