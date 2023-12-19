control 'SV-93203' do
  title 'The McAfee MOVE AV SVM must be managed by the HBSS ePO server.'
  desc 'Organizations should use centrally managed anti-virus software that is controlled and monitored regularly by anti-virus administrators, who are also typically responsible for acquiring, testing, approving, and delivering anti-virus signature and software updates throughout the organization. Users should not be able to disable or delete anti-virus software from their hosts, nor should they be able to alter critical settings.

Anti-virus administrators should perform continuous monitoring to confirm that hosts are using current anti-virus software and that the software is configured properly. Implementing all of these recommendations should strongly support an organization in having a strong and consistent anti-virus deployment across the organization.'
  desc 'check', 'Access the ePO server. 

From the system tree, select the "Systems" tab and then find and click on the asset representing the McAfee MOVE SVM to open its properties. 

If the SVM is not listed as an asset in the ePO system tree, this is a finding.'
  desc 'fix', 'In the McAfee Management for Optimized Virtual Environments AntiVirus 4.5.0 Installation Guide, follow the Agentless installation and configuration sections for Deploying the McAfee MOVE AntiVirus service (NSX), Register vCenter Server with NXS Manager and Register a VMware vCenter account with McAfee ePO.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78059r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78497'
  tag rid: 'SV-93203r1_rule'
  tag stig_id: 'MV45-SVM-200003'
  tag gtitle: 'MV45-SVM-200003'
  tag fix_id: 'F-85231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
