control 'SV-223961' do
  title 'IBM z/OS scheduled production batch ACIDs must specify the CA-TSS BATCH Facility, and the Batch Job Scheduler must be authorized to the Scheduled production CA-TSS batch ACID.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.'
  desc 'check', 'Refer to the documentation of the processes used for submission of batch jobs via an automated process (i.e., scheduler or other sources) and each of the associated userids.

Ensure that each identified batch ACID is sourced to a specific submission process used only for batch processing. 

If the following guidance is true, this is not a finding.

-The job scheduler is cross-authorized to the batch ACIDs.
-The Facility of BATCH is specified for each batch ACID.
-Batch ACIDs with facilities other than BATCH should be questioned to ensure they are truly used for batch processing only, especially if a non-expiring password is used.
-The batch ACIDS may have the NOSUSPEND attribute.'
  desc 'fix', 'Ensure associated ACIDs exist for all batch jobs and documentation justifying access to system resources is maintained and filed with the ISSO. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the required changes.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25634r516282_chk'
  tag severity: 'medium'
  tag gid: 'V-223961'
  tag rid: 'SV-223961r561402_rule'
  tag stig_id: 'TSS0-ES-000880'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-25622r516283_fix'
  tag 'documentable'
  tag legacy: ['V-98629', 'SV-107733']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
