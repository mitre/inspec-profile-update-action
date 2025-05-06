control 'SV-68717' do
  title 'The ALG that is part of a CDS must decompose information into organization-defined, policy-relevant subcomponents for submission to policy enforcement mechanisms before transferring information between different security domains.'
  desc 'Policy enforcement mechanisms apply filtering, inspection, and/or sanitization rules to the policy-relevant subcomponents of information to facilitate flow enforcement prior to transferring such information to different security domains. Parsing transfer files facilitates policy decisions on source, destination, certificates, classification, attachments, and other security-related component differentiators.

Policy enforcement mechanisms include the filtering and/or sanitization rules applied to information before transferring to a different security domain.

The organization-defined subcomponents for CDS systems depend on the environment, data, and security boundaries. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG, when transferring information between different security domains, is configured to decompose information into organization-defined, policy-relevant subcomponents for submission to policy enforcement mechanisms before transferring information between different security domains.

If the ALG is not configured to decompose information into organization-defined, policy-relevant subcomponents for submission to policy enforcement mechanisms before transferring information between different security domains, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to decompose information into organization-defined, policy-relevant subcomponents for submission to policy enforcement mechanisms before transferring information between different security domains.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55087r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54471'
  tag rid: 'SV-68717r1_rule'
  tag stig_id: 'SRG-NET-000282-ALG-000071'
  tag gtitle: 'SRG-NET-000282-ALG-000071'
  tag fix_id: 'F-59325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000219', 'CCI-000366']
  tag nist: ['AC-4 (13)', 'CM-6 b']
end
