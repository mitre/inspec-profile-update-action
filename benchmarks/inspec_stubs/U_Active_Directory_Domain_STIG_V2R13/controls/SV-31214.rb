control 'SV-31214' do
  title 'The impact of INFOCON changes on the cross-directory authentication configuration must be considered and procedures documented.'
  desc 'When incidents occur that require a change in the INFOCON status, it may be necessary to take action to restrict or disable certain types of access that is based on a directory outside the Component’s control. Cross-directory configurations (such as trusts and pass-through authentication) are specifically designed to enable resource access across directories. If conditions indicate that an outside directory is at increased risk of compromise in the immediate or near future, actions to avoid a spread of the effects of the compromise should be taken. A trusted outside directory that is compromised could allow an unauthorized user to access resources in the trusting directory.'
  desc 'check', '1. Refer to the list of actual manual AD trusts (cross-directory configurations) collected from the site representative.

2. If there are no manual AD trusts (cross-directory configurations) defined, this check is not applicable.
For AD, this includes external, forest, or realm trust relationship types.

3. Obtain a copy of the site’s supplemental INFOCON procedures as required by Strategic Command Directive (SD) 527-1.

4. Verify that it has been determined by the IAM whether INFOCON response actions need to include procedures to disable manual AD trusts (cross-directory configurations). The objective is to determine if the need has been explicitly evaluated.

5. If it has been determined that actions to disable manual AD trusts (cross-directory configurations) are not necessary, then this check is not applicable.

6. If it has been determined that actions to disable manual AD trusts (cross-directory configurations) *are* necessary, verify that the policy to implement these actions has been documented.

7. If actions to disable manual AD trusts (cross-directory configurations) *are* needed and no policy has been documented, then this is a finding.'
  desc 'fix', 'Evaluate cross-directory configurations (such as trusts and pass-through authentication) and provide documentation that indicates: 
1. That an evaluation was performed. 
2. The specific AD trust configurations, if any, that should be disabled during changes in INFOCON status because they could represent increased risk.'
  impact 0.3
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-14104r1_chk'
  tag severity: 'low'
  tag gid: 'V-8526'
  tag rid: 'SV-31214r2_rule'
  tag stig_id: 'DS00.7100_AD'
  tag gtitle: 'Cross-Directory Authentication INFOCON Procedures'
  tag fix_id: 'F-15012r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'VIIR-1, VIIR-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
