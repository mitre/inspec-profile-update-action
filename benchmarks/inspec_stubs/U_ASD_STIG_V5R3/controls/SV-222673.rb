control 'SV-222673' do
  title 'The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.'
  desc 'Many application team members may not be aware of the security implications regarding the code that they design, write and test.  To address this concern, the Program Manager will ensure all levels of program management receive security training regarding the necessity, impact, and benefits of integrating secure development practices into the development lifecycle.  

This training is in addition to DoD 8570 training requirements as DoD 8570 annual security training does not presently cover application SDLC security concerns.

The Program Manager will ensure development team members are provided training on secure design principles for the entire SDLC and newly discovered vulnerability types on, at least, an annual basis. 

Development team members include:

- Designers/Application Architects
- Developers/Programmers
- Testers
- Application managers

This requirement applies to development teams or individual application developers and does not apply when reviewing a COTS application or an application hosted at a DECC or other hosting facility when the application team is not available to interview.'
  desc 'check', 'This requirement is meant to be applied to developers and development teams only, otherwise, this requirement is not applicable.  

Interview the application representative.

Ask for evidence of annual security training for application managers, designers, developers, and testers. 

Examples of evidence include course completion certificates and a class roster. At a minimum, security training should include security awareness training pertaining to overall principles of secure application development.

Training must be in addition to DoD 8570 training requirements as DoD 8570 annual security training does not presently cover application SDLC security concerns. 

If there is no evidence of security training, this is a finding.'
  desc 'fix', 'Provide application development/operational related security specific annual training for managers, designers, developers, and testers.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24343r493927_chk'
  tag severity: 'medium'
  tag gid: 'V-222673'
  tag rid: 'SV-222673r879887_rule'
  tag stig_id: 'APSC-DV-003400'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24332r493928_fix'
  tag 'documentable'
  tag legacy: ['SV-85047', 'V-70425']
  tag cci: ['CCI-002052']
  tag nist: ['AT-3 (3)']
end
