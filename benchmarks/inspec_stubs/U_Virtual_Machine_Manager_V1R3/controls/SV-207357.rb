control 'SV-207357' do
  title 'The VMM must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations should consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

In addition, the VMM must have the capability to include organization-defined additional (more detailed) information in the audit records for audit events.'
  desc 'check', 'Verify the VMM generates audit records containing the full-text recording of privileged commands or the individual identities of group account users. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7614r365481_chk'
  tag severity: 'medium'
  tag gid: 'V-207357'
  tag rid: 'SV-207357r378631_rule'
  tag stig_id: 'SRG-OS-000042-VMM-000200'
  tag gtitle: 'SRG-OS-000042'
  tag fix_id: 'F-7614r365482_fix'
  tag 'documentable'
  tag legacy: ['SV-71151', 'V-56891']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
