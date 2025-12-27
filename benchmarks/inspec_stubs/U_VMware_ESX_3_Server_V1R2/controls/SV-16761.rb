control 'SV-16761' do
  title 'Undocumented VLANs are configured on ESX Server in VST mode.'
  desc 'When defining a physical switch port for trunk mode, care must be taken to ensure only specified VLANs are configured.  It is considered best practice to restrict only those VLANs required on the VLAN trunk link.'
  desc 'check', '1. Request from the IAO/SA the documentation that details the VLANs configured on the  physical switch port to the ESX Server.  
2. Request a copy of the external switch port configurations to verify the documented VLANs  match the configured VLANs. 
If there are undocumented VLANs configured on the external switch ports, this is a finding.'
  desc 'fix', 'Document all trunk VLANs between ESX Server and external switches.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16132r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15822'
  tag rid: 'SV-16761r1_rule'
  tag stig_id: 'ESX0310'
  tag gtitle: 'Undocumented VLANs set in VST mode.'
  tag fix_id: 'F-15774r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
