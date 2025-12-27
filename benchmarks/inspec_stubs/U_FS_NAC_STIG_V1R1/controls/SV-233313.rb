control 'SV-233313' do
  title "Forescout must be configured to notify the user before proceeding with remediation of the user's endpoint device when automated remediation is used."
  desc 'Connections that bypass established security controls should be allowed only in cases of administrative need. These procedures and use cases must be approved by the Information System Security Manager (ISSM).

This setting may be sent from the assessment server, a central server, or from the remediation server.

Verify the user is notified and accepts (e.g., using an accept button) that remediation is needed and is about to begin.'
  desc 'check', %q(Check Forescout policy to ensure that exempt devices that are in need of remediation prompt the user to accept the remediation process, prior to conducting.

1. Log on to the Forescout UI.
2. Select the "Policy" tab. 
3. Review the compliance policy identified by the site representation as the remediation policy, then click "Edit".
4. In the Sub-Rules section, select a policy and click "Edit". 
5. From the Actions section, verify that the policy is configured to notify the user, prior to remediation, that user interaction is required. 

If Forescout is not configured to notify the user before proceeding with remediation of the user's endpoint device when automated remediation is used, this is a finding.)
  desc 'fix', 'Log on to the Forescout UI.

1. Select the "Policy" tab. 
2. Select a compliance policy, then click "Edit".
3. In the Sub-Rules section, select a policy and click "Edit". 
4. From the Actions section, click Add >> Notify >> and select a notification method.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36508r615863_chk'
  tag severity: 'medium'
  tag gid: 'V-233313'
  tag rid: 'SV-233313r615864_rule'
  tag stig_id: 'FORE-NC-000050'
  tag gtitle: 'SRG-NET-000015-NAC-000070'
  tag fix_id: 'F-36473r605643_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
