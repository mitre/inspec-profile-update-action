control 'SV-207409' do
  title 'The VMM must check the validity of all data inputs except those specifically identified by the organization.'
  desc 'Invalid user input occurs when a user inserts data or characters into data entry fields and the VMM is unprepared to process that data. This results in unanticipated VMM behavior, potentially leading to a compromise. Invalid input is one of the primary methods employed when attempting to compromise a VMM. 

Checking the valid syntax and semantics of VMM inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software typically follows well-defined protocols that use structured messages (i.e., commands or queries) to communicate among guest VMs, software modules, or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If the VMM uses attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the guest VM, module, or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Pre-screening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks.'
  desc 'check', 'Verify the VMM checks the validity of all data inputs except those specifically identified by the organization.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to check the validity of all data inputs except those specifically identified by the organization.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7666r365637_chk'
  tag severity: 'medium'
  tag gid: 'V-207409'
  tag rid: 'SV-207409r379102_rule'
  tag stig_id: 'SRG-OS-000203-VMM-000750'
  tag gtitle: 'SRG-OS-000203'
  tag fix_id: 'F-7666r365638_fix'
  tag 'documentable'
  tag legacy: ['V-57019', 'SV-71279']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
