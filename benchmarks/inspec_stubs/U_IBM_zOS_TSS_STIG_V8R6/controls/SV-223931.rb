control 'SV-223931' do
  title 'IBM z/OS Started tasks must be properly defined to CA-TSS.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(STC)

For each Started Task listed If the following guidance is true, this is not a finding.

-All started tasks are assigned a unique user ACID or STC ACIDs will be unique per product and function if supported by vendor documentation.

-Every ACID with the STC Facility has a corresponding entry defined in the STC record.

-Every ACID defined in the STC record has a corresponding user ACID defined to TSS with the STC Facility.

-All STC ACIDs will have a password generated in accordance with STIG requirements.

-All STC ACIDs will be sourced to the internal reader (e.g., ADD(stc-acid) SOURCE(INTRDR).

-The STC ACIDs may have the NOSUSPEND attribute.'
  desc 'fix', 'Review the STC record and all associated ACIDs. Ensure STCs and associated ACIDs are defined to the STC record. Restrict access to required resources only. Evaluate the impact of correcting the deficiency. Ensure TSS started task table record contains an entry for each Started Proc that maps the proc to a unique userid, or STC ACIDs will be unique per product and function if supported by vendor documentation. Develop a plan of action and implement the changes as specified:

All STC ACIDs will have the STC facility. An STC also may be granted the FAC(BATCH) if it requires the capability to submit batch jobs to the internal reader. It should be noted, however, that this also will allow the STC itself to be executed as a batch job.

TSS ADD(stc-acid) FACILITY(STC BATCH)

Each STC ACID will be defined with a password following the password requirement guidelines. The only exception is that these passwords will be defined as non-expiring. In addition, each STC will have its own unique password. Defining a password for started tasks prevents a user from logging onto a system with the STC ACID.

TSS REP(stc-acid) PASSWORD(xxxxxxxx,0)

Ensure the OPTIONS control option specifies a value of 4 to disable password checking for STCs. Otherwise operators will be forced to supply a password when STCs are started. 

All STC ACIDs will be sourced to the internal reader. This control will further protect the unauthorized use of STC ACIDs.

TSS ADD(stc-acid) SOURCE(INTRDR)

Every STC will be defined to the STC table, associated with a specific procedure, and granted minimum access.

TSS ADD(STC) PROCNAME(stc-proc) ACID(stc-acid)

Note: The STC ACIDs may have the NOSUSPEND attribute to exempt an STC ACID from suspension for excessive violations. Review the STC record and all associated ACIDs. Ensure STCs and associated ACIDs are defined to the STC record. Restrict access to required resources only. Evaluate the impact of correcting the deficiency. Ensure TSS started task table record contains an entry for each Started Proc that maps the proc to a unique userid, or STC ACIDs will be unique per product and function if supported by vendor documentation. Develop a plan of action and implement the changes as specified:

All STC ACIDs will have the STC facility. An STC also may be granted the FAC(BATCH) if it requires the capability to submit batch jobs to the internal reader. It should be noted, however, that this also will allow the STC itself to be executed as a batch job.

TSS ADD(stc-acid) FACILITY(STC BATCH)

Each STC ACID will be defined with a password following the password requirement guidelines. The only exception is that these passwords will be defined as non-expiring. In addition, each STC will have its own unique password. Defining a password for started tasks prevents a user from logging onto a system with the STC ACID.

TSS REP(stc-acid) PASSWORD(xxxxxxxx,0)

Ensure the OPTIONS control option specifies a value of 4 to disable password checking for STCs. Otherwise operators will be forced to supply a password when STCs are started. 

All STC ACIDs will be sourced to the internal reader. This control will further protect the unauthorized use of STC ACIDs.

TSS ADD(stc-acid) SOURCE(INTRDR)

Every STC will be defined to the STC table, associated with a specific procedure, and granted minimum access.

TSS ADD(STC) PROCNAME(stc-proc) ACID(stc-acid)

Note: The STC ACIDs may have the NOSUSPEND attribute to exempt an STC ACID from suspension for excessive violations.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25604r516192_chk'
  tag severity: 'medium'
  tag gid: 'V-223931'
  tag rid: 'SV-223931r561402_rule'
  tag stig_id: 'TSS0-ES-000580'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-25592r516193_fix'
  tag 'documentable'
  tag legacy: ['V-98569', 'SV-107673']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
