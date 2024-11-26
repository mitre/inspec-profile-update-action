control 'SRG-NET-000138-VVSM-00102_rule' do
  title 'The Unified Communications Session Manager must be configured to use an organizational-level user account management system.'
  desc 'To effectively manage user accounts, organizational level systems such as Lightweight Directory Access Protocol (LDAP) or Active Directory (AD) are used to create and manage user credentials that can be used across the organization.

This reduces the need for separate user account databases across systems, that can create orphaned account issues, and the need to remember different credentials for each system.

When user access is no longer authorized, an organizational level system can simultaneously revoke access to all systems.'
  desc 'check', 'Verify the Unified Communications Session Manager is configured to use an organizational level user account management system.

If the Unified Communications Session Manager is not configured to use an organizational level user account management system, then is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to use an organizational level user account management system.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000138-VVSM-00102_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000138-VVSM-00102'
  tag rid: 'SRG-NET-000138-VVSM-00102_rule'
  tag stig_id: 'SRG-NET-000138-VVSM-00102'
  tag gtitle: 'SRG-NET-000138-VVSM-00102'
  tag fix_id: 'F-SRG-NET-000138-VVSM-00102_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
