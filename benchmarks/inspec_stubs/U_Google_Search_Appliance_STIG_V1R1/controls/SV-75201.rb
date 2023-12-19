control 'SV-75201' do
  title 'The Google Search Appliance must alert designated organizational officials in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Audit processing failures include; software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "System Settings".

If valid email addresses are entered, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "System Settings".

Enter valid email addresses that the audit failures need to be sent to be reviewed.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61683r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60749'
  tag rid: 'SV-75201r1_rule'
  tag stig_id: 'GSAP-00-000280'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-66429r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
