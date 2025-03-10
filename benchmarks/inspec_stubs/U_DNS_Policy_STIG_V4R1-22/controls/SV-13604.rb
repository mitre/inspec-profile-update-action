control 'SV-13604' do
  title 'A list of personnel authorized to administer each zone and name server is not maintained.'
  desc 'If an organization does not document who is responsible for the DNS function, then there is a significant potential that unauthorized individuals will obtain privileged access to name servers. During a security breach, it will be difficult to assign accountability for improper transactions if it is not known who is responsible for this function.

The roles of the SA and the DNS administrator or DNS manager are generally understood but are often used interchangeably. The SA is responsible for the OS, while the DNS administrator or DNS manager usually manages the DNS zones. In some cases, the SA is also the DNS administrator/DNS manager, which is why guidance tends to be written in a certain fashion. The application development group should refer to the supporting organization for the application when application issues arise from meeting DNS server requirements.'
  desc 'check', 'Interview the ISSO and ask for the DNS server’s documented procedures and processes.

Verify the documented procedures and processes explicitly document the roles and responsibilities for the DNS server management. These documented roles will be used to validate access controls in respective DNS technology STIGs.

In some environments, the SA is also the DNS manager. In such case, the roles should still be documented.

If the organization does not have the DNS server roles documented, this is a finding.'
  desc 'fix', 'The ISSO must create and maintain a list of authorized DNS administrators for each zone and name server under the ISSOs scope of responsibility.'
  impact 0.3
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3358r4_chk'
  tag severity: 'low'
  tag gid: 'V-13036'
  tag rid: 'SV-13604r3_rule'
  tag stig_id: 'DNS0120'
  tag gtitle: 'A list of DNS administrators is not maintained.'
  tag fix_id: 'F-4340r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
