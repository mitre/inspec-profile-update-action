control 'SV-75203' do
  title 'The Google Search Appliance must be capable of taking organization-defined actions upon audit failure (e.g., overwrite oldest audit records, stop generating audit records, cease processing, notify of audit failure).'
  desc 'It is critical when a system is at risk of failing to process audit logs as required; it detects and takes action to mitigate the failure.  Audit processing failures include:  software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.  Applications are required to be capable of either directly performing or calling system level functionality performing defined actions upon detection of an application audit log processing failure.'
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
  tag check_id: 'C-61685r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60751'
  tag rid: 'SV-75203r1_rule'
  tag stig_id: 'GSAP-00-000285'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-66431r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
