control 'SV-75199' do
  title 'The Google Search Appliance must provide a real-time alert when all audit failure events occur.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Audit processing failures include:  software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 

Organizations must define audit failure events requiring an application to send an alarm.  When those defined events occur, the application will provide a real-time alert to the appropriate personnel.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "System Settings".

If only valid emails addresses are entered, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "System Settings".

Enter valid email addresses that the audit failures need to be sent to be reviewed.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61681r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60747'
  tag rid: 'SV-75199r1_rule'
  tag stig_id: 'GSAP-00-000275'
  tag gtitle: 'SRG-APP-000104'
  tag fix_id: 'F-66427r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000144']
  tag nist: ['AU-5 (2)']
end
