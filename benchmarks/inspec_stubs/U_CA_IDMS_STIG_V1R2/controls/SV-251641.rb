control 'SV-251641' do
  title 'IDMS terminal and lines that are not secure must be disabled.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', 'For each load area, run a CREPORT 43 to check the nodes and access types for each node. For each node, issue DCMT D LINE. For each LINE type with a status of InSrv, inspect the access type for potential unauthorized connection types. 

For TCP/IP, any line with access type SOCKET, issue DCMT D LINE <tcp-line-id>. If any terminals are of type LIST and status InSrv, check port number for a valid port. If the port number is unacceptable as defined in the PPSM CAL, this is a finding. 

For each terminal with the type of LIST and InSrv, issue DCMT D PTE <pterm-id>. For each task and (possible PARM STRING which could pass a task) identified in the PTE display, issue DCMT D TASK <task-id>. If the task is IDMSJSRV and the associated program is RHDCNP3J, this is not a finding. If the task/program has not been authorized, this is a finding. 

If other access types (e.g., VTAM, SVC, CCI) have been deemed nonsecure in the PPSM CAL, this is a finding.'
  desc 'fix', 'For any pterm found to have nonsecure attributes (task, program, port), disable by issuing DCMT V PTE <pterm-id> OFF. 

Using SYSGEN, remove offending lines, pterms, lterms, and/or port numbers and regenerate the system.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55076r807788_chk'
  tag severity: 'medium'
  tag gid: 'V-251641'
  tag rid: 'SV-251641r855279_rule'
  tag stig_id: 'IDMS-DB-000770'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-55030r807789_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
