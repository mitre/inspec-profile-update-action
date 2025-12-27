control 'SV-207366' do
  title 'The VMM must provide audit record generation capability for DoD-defined auditable events for all VMM components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter). 

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 

DoD has defined the list of events for which the VMM will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the VMM;

(iii) All account creations, modifications, disabling, and terminations; and 

(iv) All kernel module load, unload, and restart actions.'
  desc 'check', 'Verify the VMM provides audit record generation capability for DoD-defined auditable events for all VMM components.

If it does not, this is a finding.

DoD has defined the list of events for which the VMM will provide an audit record generation capability as the following:

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the VMM;

(iii) All account creations, modifications, disabling, and terminations; and 

(iv) All kernel module load, unload, and restart actions.'
  desc 'fix', 'Configure the VMM to provide audit record generation capability for DoD-defined auditable events for all VMM components.

DoD has defined the list of events for which the VMM will provide an audit record generation capability as the following:

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the VMM;

(iii) All account creations, modifications, disabling, and terminations; and 

(iv) All kernel module load, unload, and restart actions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7623r365508_chk'
  tag severity: 'medium'
  tag gid: 'V-207366'
  tag rid: 'SV-207366r378721_rule'
  tag stig_id: 'SRG-OS-000062-VMM-000300'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-7623r365509_fix'
  tag 'documentable'
  tag legacy: ['V-56915', 'SV-71175']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
