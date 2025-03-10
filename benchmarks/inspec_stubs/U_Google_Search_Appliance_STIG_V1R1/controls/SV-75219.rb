control 'SV-75219' do
  title 'The Google Search Appliance must support the requirement to back up audit data and records onto a different system or media than the system being audited at least every seven days.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted.  Backing up audit records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "Network Settings".

If the "Facility" setting is enabled, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "Network Settings".

Ensure that "Facility" setting is enabled.

Click Save.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61689r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60767'
  tag rid: 'SV-75219r1_rule'
  tag stig_id: 'GSAP-00-000360'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-66447r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
