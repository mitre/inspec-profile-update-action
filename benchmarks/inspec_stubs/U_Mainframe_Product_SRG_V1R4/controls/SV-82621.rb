control 'SV-82621' do
  title 'The Mainframe Product must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the application must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If temporary users are not removed or disabled after 72 hours, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically remove or disable temporary user accounts after 72 hours.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68689r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68131'
  tag rid: 'SV-82621r1_rule'
  tag stig_id: 'SRG-APP-000024-MFP-000036'
  tag gtitle: 'SRG-APP-000024-MFP-000036'
  tag fix_id: 'F-74247r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
