control 'SV-223949' do
  title 'Started tasks must be properly defined to CA-TSS.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Refer to a list of all started tasks (STCs) and associated userids with a brief description on the system.

If the following guidance is true, this is not a finding.

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

-All STC ACIDs will be sourced to the internal reader. This control will further protect the unauthorized use of STC ACIDs.

TSS ADD(stc-acid) SOURCE(INTRDR)

-Every STC will be defined to the STC table, associated with a specific procedure, and granted minimum access.

-TSS ADD(STC) PROCNAME(stc-proc) ACID(stc-acid)

Note: The STC ACIDs may have the NOSUSPEND attribute to exempt an STC ACID from suspension for excessive violations. Review the STC record and all associated ACIDs. Ensure STCs and associated ACIDs are defined to the STC record. Restrict access to required resources only. Evaluate the impact of correcting the deficiency. Ensure TSS started task table record contains an entry for each Started Proc that maps the proc to a unique userid, or STC ACIDs will be unique per product and function if supported by vendor documentation. Develop a plan of action and implement the changes as specified:

-All STC ACIDs will have the STC facility. An STC also may be granted the FAC(BATCH) if it requires the capability to submit batch jobs to the internal reader. It should be noted, however, that this also will allow the STC itself to be executed as a batch job.

TSS ADD(stc-acid) FACILITY(STC BATCH)

-Each STC ACID will be defined with a password following the password requirement guidelines. The only exception is that these passwords will be defined as non-expiring. In addition, each STC will have its own unique password. Defining a password for started tasks prevents a user from logging onto a system with the STC ACID.

TSS REP(stc-acid) PASSWORD(xxxxxxxx,0)

-Ensure the OPTIONS control option specifies a value of 4 to disable password checking for STCs. Otherwise operators will be forced to supply a password when STCs are started. 

-All STC ACIDs will be sourced to the internal reader. This control will further protect the unauthorized use of STC ACIDs.

TSS ADD(stc-acid) SOURCE(INTRDR)

-Every STC will be defined to the STC table, associated with a specific procedure, and granted minimum access.

TSS ADD(STC) PROCNAME(stc-proc) ACID(stc-acid)

Note: The STC ACIDs may have the NOSUSPEND attribute to exempt an STC ACID from suspension for excessive violations.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25622r516246_chk'
  tag severity: 'medium'
  tag gid: 'V-223949'
  tag rid: 'SV-223949r561402_rule'
  tag stig_id: 'TSS0-ES-000760'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25610r516247_fix'
  tag 'documentable'
  tag legacy: ['SV-107709', 'V-98605']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
