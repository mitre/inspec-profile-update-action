control 'SV-237959' do
  title 'CA VM:Secure product AUTHORIZ CONFIG file must be restricted to appropriate personnel.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

The AUTHORIZ CONFIG file is used to tailor user authorizations for CA VM:Secure commands.'
  desc 'check', 'Query the CA VM:Secure product rules.

If there are product rules granting access to the disk on which the “AUTHORIZ CONFIG” file resides for system administrators or security administrators only, this is not a finding.'
  desc 'fix', 'Create rules in the CA VM:Secure product Rules Facility that restricts access to the disk where the “AUTHORIZ CONFIG” file resides to system administrators or security administrators only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41169r649715_chk'
  tag severity: 'medium'
  tag gid: 'V-237959'
  tag rid: 'SV-237959r649717_rule'
  tag stig_id: 'IBMZ-VM-001240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-41128r649716_fix'
  tag 'documentable'
  tag legacy: ['SV-93671', 'V-78965']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
