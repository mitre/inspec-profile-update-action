control 'SV-223672' do
  title 'IBM RACF batch jobs must be properly secured.'
  desc 'Batch jobs that are submitted to the operating system should inherit the USERID of the submitter. This will identify the batch job with a userid for the purpose of accessing resources. BATCHALLRACF ensures that a valid USERID is associated with batch jobs. Jobs that are submitted to the operating system via a scheduling facility must also be identified to the system. Without a batch job having an associated USERID, access to system resources will be limited.

'
  desc 'check', 'Refer to the documentation of the processes used for submission of batch jobs via an automated process (i.e., scheduler or other sources) and each of the associated userids. Determine any other scheduled batch jobs on the system.

From an ISPF Command Shell enter:
RLIST SURROGAT *

If each batch job userid used for batch submission by a Job Scheduler (e.g., CONTROL-M, CA-7, CA-Scheduler, etc.) is defined as an execution-userid in a SURROGAT resource class profile, this is not a finding.

From an ISPF Command Shell enter:
RLIST SURROGAT <surrogat-userid> ALL

If the Job Scheduler userids (i.e., surrogate-userid) are permitted surrogate authority to the appropriate SURROGAT profiles, this is not a finding.'
  desc 'fix', 'Configure each batch job userid used for batch submission by a Job Scheduler (e.g., CONTROL-M, CA-7, CA-Scheduler, etc.) is defined as an execution-userid in a SURROGAT resource class profile. For example:

RDEFINE SURROGAT execution-userid.SUBMIT UACC(NONE)
OWNER(execution-userid)

Configure Job Scheduler userids (i.e., surrogate-userid) are permitted surrogate authority to the appropriate SURROGAT profiles. For example:

PERMIT execution-userid.SUBMIT CLASS(SURROGAT)
ID(surrogate-userid) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25345r516739_chk'
  tag severity: 'medium'
  tag gid: 'V-223672'
  tag rid: 'SV-223672r604139_rule'
  tag stig_id: 'RACF-ES-000240'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25333r516740_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000326-GPOS-00126']
  tag 'documentable'
  tag legacy: ['V-98049', 'SV-107153']
  tag cci: ['CCI-000213', 'CCI-002233']
  tag nist: ['AC-3', 'AC-6 (8)']
end
