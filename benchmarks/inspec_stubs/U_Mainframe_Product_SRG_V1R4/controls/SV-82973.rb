control 'SV-82973' do
  title 'The Mainframe Product must remove all upgraded/replaced software components that are no longer required for operation after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Examine inventory of installed software components for the Mainframe Product.

If the Mainframe Product does not remove all upgraded/replaced software components that are no longer required for operation, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to remove all upgraded/replaced software components that are no longer required for operation.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69015r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68483'
  tag rid: 'SV-82973r1_rule'
  tag stig_id: 'SRG-APP-000454-MFP-000343'
  tag gtitle: 'SRG-APP-000454-MFP-000343'
  tag fix_id: 'F-74599r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
