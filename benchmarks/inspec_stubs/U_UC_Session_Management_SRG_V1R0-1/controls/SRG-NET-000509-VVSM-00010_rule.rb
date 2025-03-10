control 'SRG-NET-000509-VVSM-00010_rule' do
  title 'When using locally stored user accounts, the Unified Communications Session Manager must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

This requirement only applies to components where this is specific to the function of the device, such as application layer gateway (ALG), which provides these access control and auditing functions on behalf of an application. This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the Unified Communications Session Manager, when using locally stored user accounts, is configured to generate audit records for all account creation, modification, disabling, and termination events.

If the Unified Communications Session Manager is not configured to generate audit records for all account creation, modification, disabling, and termination events, this is a finding.'
  desc 'fix', 'When using locally stored user accounts, configure the Unified Communications Session Manager to generate audit records for all account creation, modification, disabling, and termination events.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000509-VVSM-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000509-VVSM-00010'
  tag rid: 'SRG-NET-000509-VVSM-00010_rule'
  tag stig_id: 'SRG-NET-000509-VVSM-00010'
  tag gtitle: 'SRG-NET-000509-VVSM-00010'
  tag fix_id: 'F-SRG-NET-000509-VVSM-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
