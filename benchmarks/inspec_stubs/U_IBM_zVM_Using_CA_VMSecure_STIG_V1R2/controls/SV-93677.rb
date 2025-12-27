control 'SV-93677' do
  title 'CA VM:Secure product Rules Facility must be restricted to appropriate personnel.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Issue Command:

VMSECURE CONFIG AUTHORIZ

Inspect the "GRANT" statements.

If there are statements that grant the authority to create system rules or rules that apply to other users is only granted to appropriate personnel, this is not a finding.'
  desc 'fix', 'Ensure the product Rules Facility is installed.

Ensure that authority to create system rules or rules that apply to other users is only granted to appropriate personnel.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78559r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78971'
  tag rid: 'SV-93677r1_rule'
  tag stig_id: 'IBMZ-VM-001280'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85721r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
