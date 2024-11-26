control 'SV-68743' do
  title 'The ALG that is part of a CDS must enforce the use of human reviews for organization-defined information flows under organization-defined conditions.'
  desc 'Without network element enforcement of human reviews, security policy filters may have false positives and false negatives in marginal situations, which may result in loss of confidentiality or availability.

Organizations define security policy filters for all situations where automated flow control decisions are possible. When a fully automated flow control decision is not possible, then a human review may be employed in lieu of, or as a complement to, automated security policy filtering. Human reviews may also be employed as deemed necessary by organizations.

The cross domain solution will display the data which requires human review to the authorized reviewer in its native form (i.e., consistent with how it would be displayed by the application that created the data). The system will require a response from the authorized reviewer prior to taking action on the transfer data and then take appropriate actions as indicated by the reviewer (e.g., reject, forward, reply, etc.), but do not allow the reviewer to circumvent any additional filtering mechanisms.

Organization-defined information flows and conditions used as part of a CDS system depend on the environment, data, and security boundaries. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG is configured to enforce the use of human reviews for organization-defined information flows under organization-defined conditions.

If the ALG is not configured to enforce the use of human reviews for organization-defined information flows under organization-defined conditions, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to enforce the use of human reviews for organization-defined information flows under organization-defined conditions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55113r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54497'
  tag rid: 'SV-68743r1_rule'
  tag stig_id: 'SRG-NET-000329-ALG-000084'
  tag gtitle: 'SRG-NET-000329-ALG-000084'
  tag fix_id: 'F-59351r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002198']
  tag nist: ['CM-6 b', 'AC-4 (9)']
end
