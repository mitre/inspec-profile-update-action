control 'SV-223577' do
  title 'IBM z/OS System Administrator must develop a procedure to automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system administrator for the procedure to automatically remove or disable temporary user accounts after 72 hours.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to automatically remove or disable temporary user accounts after 72 hours.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25250r500866_chk'
  tag severity: 'medium'
  tag gid: 'V-223577'
  tag rid: 'SV-223577r533198_rule'
  tag stig_id: 'ACF2-OS-002370'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-25238r500867_fix'
  tag 'documentable'
  tag legacy: ['SV-106963', 'V-97859']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
