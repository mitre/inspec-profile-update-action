control 'SV-93221' do
  title 'The McAfee MOVE AV Common Options policy must be configured to enable self-protection.'
  desc %q(The self-protection feature defends files, services, and registry keys on virtual machines and will ensure uninterrupted protection.

Self-protection on the McAfee MOVE SVM is provided by the SVM's VirusScan Enterprise Access Protection configuration.

The self-protection feature is controlled by the IntegrityEnabled configuration parameter. By default, the parameter is set to "0x7", and all components of the feature are enabled.)
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus Common 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Self-Protection", confirm "Enable Self-Protection" and "Enable Self-Protection for MOVE CLI" check boxes are both selected.

If either "Enable Self-Protection" or "Enable Self-Protection for MOVE CLI" check boxes are not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus Common 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Self-Protection", select the "Enable Self-Protection" and "Enable Self-Protection for MOVE CLI" check boxes.

Click "Save".'
  impact 0.7
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78077r1_chk'
  tag severity: 'high'
  tag gid: 'V-78515'
  tag rid: 'SV-93221r1_rule'
  tag stig_id: 'MV45-COP-000004'
  tag gtitle: 'MV45-COP-000004'
  tag fix_id: 'F-85249r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
