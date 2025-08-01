control 'SV-233168' do
  title 'The container platform must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure applications have a sufficient storage capacity in which to write the audit logs, applications need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the application and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.'
  desc 'check', 'Review the container platform configuration to determine if audit record storage capacity is allocated in accordance with organization-defined audit record storage requirements. 

If audit record storage capacity is not allocated in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the container platform to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36104r599624_chk'
  tag severity: 'medium'
  tag gid: 'V-233168'
  tag rid: 'SV-233168r599625_rule'
  tag stig_id: 'SRG-APP-000357-CTR-000800'
  tag gtitle: 'SRG-APP-000357'
  tag fix_id: 'F-36072r599141_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
