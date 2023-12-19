control 'SV-75185' do
  title 'To support DoD requirements to centrally manage the content of audit records, Google Search Appliances must provide the ability to write specified audit record content to a centralized audit log repository.'
  desc 'Information system auditing capability is critical for accurate forensic analysis.  Audit record content that may be necessary to satisfy the requirement of this control, includes but is not limited:  time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application specific events, success/fail indications, filenames involved, access control or flow control rules invoked. 

Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.  When organizations define application components requiring centralized audit log management, applications need to support that requirement.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.

Navigate to "Administration", select "Network Settings".

If a valid Syslog server is entered, this is not a finding.'
  desc 'fix', %q(Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "Network Settings".

Enter a valid Syslog server information.

Click Save.

Notes: Centralized logging provides the search appliance logs user search queries. If the Syslog Server value is set, the search appliance sends the log messages to the syslog server every five minutes, assigning the messages the priority "Informational." If there weren't any new searches between the previous run and the new run, the search appliance doesn't send anything to the syslog server.)
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61679r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60733'
  tag rid: 'SV-75185r1_rule'
  tag stig_id: 'GSAP-00-000265'
  tag gtitle: 'SRG-APP-000102'
  tag fix_id: 'F-66413r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
