control 'SV-82959' do
  title 'The Mainframe Product must isolate security functions from nonsecurity functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. 

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Applications restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Examine installation and configuration settings. 

Security modules should be loaded into different datasets than nonsecurity modules.

If the Mainframe Product does not differentiate between security and nonsecurity functions and provide procedure to isolate the functions, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to load security modules into a separate dataset than nonsecurity modules.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69001r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68469'
  tag rid: 'SV-82959r1_rule'
  tag stig_id: 'SRG-APP-000233-MFP-000305'
  tag gtitle: 'SRG-APP-000233-MFP-000305'
  tag fix_id: 'F-74585r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
