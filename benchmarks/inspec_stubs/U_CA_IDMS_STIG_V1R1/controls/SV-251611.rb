control 'SV-251611' do
  title 'IDMS nodes, lines, and pterms must be protected from unauthorized use.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.

Unused nodes, lines, and ports must be secured to prevent unauthorized use.'
  desc 'check', 'For each load area, run a CREPORT 43 to check the nodes and access types for each node. For each node, issue DCMT D LINE. For each LINE type with a status of InSrv, inspect the access type for potential unauthorized connection types. 

For TCP/IP, any line with access type SOCKET, issue DCMT D LINE <tcp-line-id>. If any terminals are of type LIST and status InSrv, check port number for a valid port. If the port number is unacceptable as defined in the PPSM CAL, this is a finding.

For each terminal with the type of LIST and InSrv, issue DCMT D PTE <pterm-id>. For each task and (possible PARM STRING which could pass a task) identified in the PTE display, issue DCMT D TASK <task-id>. If the task is IDMSJSRV and the associated program is not RHDCNP3J, this is a finding. 

If the task/program has not been authorized, this is a finding. 

If other access types (e.g., VTAM, SVC, CCI) have been deemed nonsecure in the PPSM CAL, this is a finding.'
  desc 'fix', 'For any pterm found to have nonsecure attributes (task, program, or port), disable by issuing DCMT V PTE <pterm-id> OFF. Using SYSGEN, remove offending lines, pterms, lterms, and/or port numbers, then validate and regenerate the system.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55046r807698_chk'
  tag severity: 'medium'
  tag gid: 'V-251611'
  tag rid: 'SV-251611r807700_rule'
  tag stig_id: 'IDMS-DB-000310'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-55000r807699_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
