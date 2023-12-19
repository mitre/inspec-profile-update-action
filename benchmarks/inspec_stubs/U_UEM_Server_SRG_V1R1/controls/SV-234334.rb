control 'SV-234334' do
  title 'The UEM server must be configured to generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

In addition, the application must have the capability to include organization-defined additional, more detailed information in the audit records for audit events. 

Satisfies:FAU_GEN.1.2(1) 
Reference:PP-MDM-412060'
  desc 'check', 'Verify the UEM server generates audit records containing the full-text recording of privileged commands or the individual identities of group account users.

If the UEM server does not generate audit records containing the full-text recording of privileged commands or the individual identities of group account users, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37519r614012_chk'
  tag severity: 'medium'
  tag gid: 'V-234334'
  tag rid: 'SV-234334r617355_rule'
  tag stig_id: 'SRG-APP-000101-UEM-000061'
  tag gtitle: 'SRG-APP-000101'
  tag fix_id: 'F-37484r614013_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
