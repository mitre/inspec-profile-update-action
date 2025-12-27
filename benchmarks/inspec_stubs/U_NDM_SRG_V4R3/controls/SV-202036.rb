control 'SV-202036' do
  title 'The network device must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Determine if the network device generates audit records containing the full-text recording of privileged commands. If such audit records are not being generated, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records containing the full-text recording of privileged commands.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2162r381674_chk'
  tag severity: 'medium'
  tag gid: 'V-202036'
  tag rid: 'SV-202036r879569_rule'
  tag stig_id: 'SRG-APP-000101-NDM-000231'
  tag gtitle: 'SRG-APP-000101'
  tag fix_id: 'F-2163r381675_fix'
  tag 'documentable'
  tag legacy: ['SV-69393', 'V-55147']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
