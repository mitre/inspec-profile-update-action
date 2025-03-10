control 'SV-224035' do
  title 'IBM z/OS system administrator must develop a procedure to remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system administrator for the procedure to automatically remove or disable temporary user accounts after 72 hours.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to remove or disable emergency user accounts after the crisis is resolved or 72 hours.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25708r516504_chk'
  tag severity: 'medium'
  tag gid: 'V-224035'
  tag rid: 'SV-224035r877873_rule'
  tag stig_id: 'TSS0-OS-000390'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-25696r516505_fix'
  tag 'documentable'
  tag legacy: ['SV-107883', 'V-98779']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
