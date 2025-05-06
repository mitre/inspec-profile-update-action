control 'SV-77439' do
  title 'Riverbed Optimization System (RiOS) must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Verify that RiOS is configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments.

Navigate to the device Management Console
Navigate to Configure >> Security >> Management ACL

Verify that this page contains all unnecessary and/or nonsecure functional, ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments.
Verify that "Enable Management ACL" is checked.

If no PPSM CAL or vulnerability assessment information is presented on this page or "Enable Management ACL" is not checked, this is a finding.'
  desc 'fix', 'Configure RiOS to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services , as defined in the PPSM CAL and vulnerability assessments.

Navigate to the device Management Console
Navigate to Configure >> Security >> Management ACL
Click "Add a New Rule"
Set the values in "Management ACL Settings" to match requirements defined in the PPSM CAL and vulnerability assessments
Check the field "Enable Management ACL"
Click "Apply"
Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63701r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62949'
  tag rid: 'SV-77439r1_rule'
  tag stig_id: 'RICX-DM-000096'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-68867r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
