control 'SV-223673' do
  title 'IBM RACF batch jobs must be protected with propagation control.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Refer to a list all Multiple User Access Systems in use on this system. These are systems that run in a single address space, but allow multiple users to sign on to them (e.g., CICS regions, Session Managers, etc.). For each region, also include corresponding userids, profiles, data management files, and a brief description (of each region). 

Refer to the documentation of the processes used for submission of batch jobs via an automated process (i.e., scheduler or other sources) and each of the associated userids.

If the submission of batch jobs via an automated process (e.g., job scheduler, job submission started task, etc.) is being utilized, and/or Multiple User Single Address Space Systems (MUSASS) capable of submitting batch jobs are active on this system and the following items are in effect, this is not a finding.

The PROPCNTL resource class is active.
A PROPCNTL resource class profile is defined for each userid associated with a job scheduler (e.g., CONTROL-M, CA-7, etc.) and a MUSASS able to submit batch jobs (e.g., CA-ROSCOE, etc.).'
  desc 'fix', 'Add a PROPCNTL profile for each userid associated with a job scheduler (e.g., CONTROL-M, CA-7, etc.) or a MUSASS able to submit batch jobs (e.g., CA-ROSCOE, etc.). 

A sample command is shown here:
RDEF PROPCNTL controlm UACC(NONE) OWNER(ADMIN)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25346r516742_chk'
  tag severity: 'medium'
  tag gid: 'V-223673'
  tag rid: 'SV-223673r604139_rule'
  tag stig_id: 'RACF-ES-000250'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25334r516743_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000326-GPOS-00126']
  tag 'documentable'
  tag legacy: ['SV-107155', 'V-98051']
  tag cci: ['CCI-000213', 'CCI-002233']
  tag nist: ['AC-3', 'AC-6 (8)']
end
