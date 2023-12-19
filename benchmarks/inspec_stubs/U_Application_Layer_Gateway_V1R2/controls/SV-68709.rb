control 'SV-68709' do
  title 'The ALG that is part of a CDS must use source and destination security attributes associated with organization-defined information, source, and/or destination objects to enforce organization-defined information flow control policies as a basis for flow control decisions.'
  desc 'If information flow is not enforced based on approved authorizations, the system may become compromised.

A mechanism to detect and prevent unauthorized communication flow must be configured and used to filter information flow across security boundaries protected by the ALG. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. Security attributes may be used to manage information flow control.

Organization-defined information and organization-defined information flow control policies for CDS systems depend on the environment, data, and security boundaries. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.

Information flow enforcement mechanisms compare security attributes associated with information (data content and data structure) and/or source/destination objects. The ALG uses the result of the attribute-object comparison to take an organization-defined action based on configured rules. Security attributes most often include source and destination addresses.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG uses source and destination security attributes associated with organization-defined information, source, and/or destination objects to enforce organization-defined information flow control policies as a basis for flow control decisions.

If the ALG is not configured to use source and destination security attributes associated with organization-defined information, source, and/or destination objects to enforce organization-defined information flow control policies as a basis for flow control decisions, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to use source and destination security attributes associated with organization-defined information, source, and/or destination objects to enforce organization-defined information flow control policies as a basis for flow control decisions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55079r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54463'
  tag rid: 'SV-68709r1_rule'
  tag stig_id: 'SRG-NET-000323-ALG-000067'
  tag gtitle: 'SRG-NET-000323-ALG-000067'
  tag fix_id: 'F-59317r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002190']
  tag nist: ['CM-6 b', 'AC-4 (1)']
end
