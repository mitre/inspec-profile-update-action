control 'SV-220362' do
  title 'MarkLogic Server must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', 'Review the DBMS settings and local documentation for functions, ports, protocols, and services that are approved. 

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to check resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Inspect the list of App Servers and associated Protocols and Ports.
5. If any App Server has an associated protocol or port that is not approved, this is a finding.'
  desc 'fix', 'Disable functions, ports, protocols, and services that are not approved.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to check resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Inspect the list of App Servers and associated Protocols and Ports.
5. If any App Server has an associated protocol or port that is not approved, remove the App Server by selecting the server and selecting either "Disable" or "Delete".'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22077r401537_chk'
  tag severity: 'medium'
  tag gid: 'V-220362'
  tag rid: 'SV-220362r622777_rule'
  tag stig_id: 'ML09-00-003400'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-22066r401538_fix'
  tag 'documentable'
  tag legacy: ['SV-110071', 'V-100967']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
