control 'SV-203686' do
  title 'The operating system must control remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify the operating system controls remote access methods. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to control remote access methods.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3811r374945_chk'
  tag severity: 'medium'
  tag gid: 'V-203686'
  tag rid: 'SV-203686r379450_rule'
  tag stig_id: 'SRG-OS-000297-GPOS-00115'
  tag gtitle: 'SRG-OS-000297'
  tag fix_id: 'F-3811r374946_fix'
  tag 'documentable'
  tag legacy: ['SV-71473', 'V-57213']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
