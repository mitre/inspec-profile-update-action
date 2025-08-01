control 'SV-82747' do
  title 'The mainframe product must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure applications have a sufficient storage capacity in which to write the audit logs, applications need to be able to allocate audit record storage capacity. 

The task of allocating audit record storage capacity is usually performed during initial installation of the application and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.'
  desc 'check', 'If the Mainframe Product uses MVS System Management Facility (SMF) recording or ESM log files for auditing purposes, this is not applicable.

Examine the Mainframe Product installation and configuration auditing settings.

If the installation and/or configuration setting for auditing do not allocate audit record storage capacity in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure installation and/or configuration auditing settings to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68257'
  tag rid: 'SV-82747r1_rule'
  tag stig_id: 'SRG-APP-000357-MFP-000148'
  tag gtitle: 'SRG-APP-000357-MFP-000148'
  tag fix_id: 'F-74371r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
