control 'SV-240946' do
  title 'The vAMI installation procedures must be part of a complete vRealize Automation deployment.'
  desc 'Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. When an application is deployed to the vAMI, if the deployment process does not complete properly and without errors, there is the potential that some application files may not be deployed or may be corrupted and an application error may occur during runtime. The vAMI must be able to perform complete application deployments. A partial deployment can leave the server in an inconsistent state. Application servers may provide a transaction rollback function to address this issue.'
  desc 'check', 'Interview the ISSO and/or the SA.
 
Determine if the vAMI was installed separately from a full installation of vRealize Automation.
 
If the vAMI was installed independently of a full vRA installation, this is a finding.'
  desc 'fix', 'Reinstall the vRealize Automation instance as a complete package.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44179r676003_chk'
  tag severity: 'medium'
  tag gid: 'V-240946'
  tag rid: 'SV-240946r879640_rule'
  tag stig_id: 'VRAU-VA-000310'
  tag gtitle: 'SRG-APP-000225-AS-000153'
  tag fix_id: 'F-44138r676004_fix'
  tag 'documentable'
  tag legacy: ['SV-100885', 'V-90235']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
