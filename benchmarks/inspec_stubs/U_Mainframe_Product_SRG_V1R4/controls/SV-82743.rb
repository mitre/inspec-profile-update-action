control 'SV-82743' do
  title 'The Mainframe Product must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

In addition, the application must have the capability to include organization-defined additional, more detailed information in the audit records for audit events.'
  desc 'check', 'Examine installation and configuration settings.

Verify data written to external security manager audit files and/or SMF records contain information that details contain full-text recording of privileged commands or the individual identities of group account users associated with the event. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit records written to external security manager audit files and/or SMF records to contain full-text recording of privileged commands or the individual identities of group account users.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68253'
  tag rid: 'SV-82743r1_rule'
  tag stig_id: 'SRG-APP-000101-MFP-000146'
  tag gtitle: 'SRG-APP-000101-MFP-000146'
  tag fix_id: 'F-74367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
