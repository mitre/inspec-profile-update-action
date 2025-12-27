control 'SV-93623' do
  title 'The IBM z/VM Privilege command class A and Class B must be properly assigned.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Operating system functionality will vary, and while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages, such as from an approved software repository.

The operating system or software configuration management utility must enforce control of software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.'
  desc 'check', 'Examine CP Directory.

If Privilege CLASS A or B is granted to anyone other than systems administrators or systems operators, this is a finding.

Note: Restrict link to disk where system software resides.'
  desc 'fix', 'Configure the IBM z/VM to grant CP Privilege Class A or B to system administrators or system operators only.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78503r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78917'
  tag rid: 'SV-93623r1_rule'
  tag stig_id: 'IBMZ-VM-000900'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-85667r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
