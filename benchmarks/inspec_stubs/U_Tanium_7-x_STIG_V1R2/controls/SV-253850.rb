control 'SV-253850' do
  title 'The Tanium Application Server must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM Category Assurance List (CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or address authorized quality-of-life issues.'
  desc 'check', 'Review the PPSM CAL to verify Tanium has been registered with all of the TCP ports required for functionality to include (but not limited to) TCP 17472, 17477, 17440, 17441, 443, and 1433.

If any TCP ports are being used on the Tanium Server that have been deemed as restricted by the PPSM CAL, this is a finding.'
  desc 'fix', 'Submit a formal request to have the Tanium communication ports evaluated and added to the PPSM CAL.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57302r842576_chk'
  tag severity: 'medium'
  tag gid: 'V-253850'
  tag rid: 'SV-253850r842578_rule'
  tag stig_id: 'TANS-SV-000019'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-57253r842577_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
