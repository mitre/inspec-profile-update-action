control 'SV-223578' do
  title 'IBM z/OS system administrator must develop a procedure to automatically remove or disable emergency accounts after the crisis is resolved or 72 hours.'
  desc "Emergency accounts are privileged accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability. 

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by the organization's system administrators when network or normal logon/access is not available). Infrequently used accounts are not subject to automatic termination dates. Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
  desc 'check', 'Ask the system administrator for the procedure to automatically remove or disable emergency accounts after the crisis is resolved or 72 hours.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to remove or disable emergency user accounts after the crisis is resolved or 72 hours.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25251r500869_chk'
  tag severity: 'medium'
  tag gid: 'V-223578'
  tag rid: 'SV-223578r533198_rule'
  tag stig_id: 'ACF2-OS-002380'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-25239r500870_fix'
  tag 'documentable'
  tag legacy: ['V-97861', 'SV-106965']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
