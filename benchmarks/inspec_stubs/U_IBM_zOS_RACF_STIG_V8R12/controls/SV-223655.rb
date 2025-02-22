control 'SV-223655' do
  title 'IBM z/OS system commands must be properly protected.'
  desc 'z/OS system commands provide a method of controlling the operating environment. Failure to properly control access to z/OS system commands could result in unauthorized personnel issuing sensitive system commands. This exposure may threaten the integrity and availability of the operating system environment, and compromise the confidentiality of customer data.'
  desc 'check', 'From the ISPF Command Shell enter:
RList OPERCMDS *

If the MVS.** resource is defined to the OPERCMDS class with an access of NONE and all (i.e., failures and successes) access logged, this is not a finding.

If the access to z/OS system commands defined in the table entitled MVS commands, RACF access authorities, and resource names, in the IBM z/OS MVS System Commands manual, is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users) as determined in the Documented site Security Plan, this is not a finding.

Note: Display commands and others as deemed by the site IAW site security plan may be allowed for all users with no logging. The (MVS.SEND) Command will not be a finding if used by all.

If all access (i.e., failures and successes) to specific z/OS system commands is logged as indicated in the table entitled MVS commands, RACF access authorities, and resource names, in the z/OS MVS System Commands, this is not a finding.'
  desc 'fix', %q(z/OS system commands provide control over z/OS functions and can compromise security if misused. These commands are subject to various types of potential abuse. For this reason, it is necessary to place restrictions on the z/OS system commands that can be entered by particular operators.

Some commands are particularly dangerous and should only be used when all less drastic options have been exhausted. Misuse of these commands can create a situation in which the only recovery is an IPL.

Apply the following recommendations when implementing security:

The MVS.** resource is defined to the OPERCMDS class with an access of NONE and all (i.e., failures and successes) access logged.

Access to z/OS system commands defined in the entitled MVS commands, RACF access authorities, and resource names, in the IBM z/OS MVS System Commands manual is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users).

The (MVS.SEND) Command will not be a finding if used by all.

Display commands and others as deemed by the site IAW site security plan may be allowed for all users with no logging. The (MVS.SEND) Command will not be a finding if used by all.

All elevated access (i.e., failures and successes) to specific z/OS system commands is logged.

A sample set of commands to define and permit access to system command resources is shown here:

RDEF OPERCMDS MVS.** UACC(NONE) OWNER(<syspsmpl>) AUDIT(ALL(READ)) DATA("set up deny-by-default profile')

Then, in accordance with the referenced table, use the following template to define profiles for each command:

RDEF OPERCMDS <system command profile> UACC(NONE) OWNER(<syspsmpl>) AUDIT(ALL(READ))

PERMIT <system command profile> CLASS(OPERCMDS) ID(<groupname>) ACCESS(<accesslevel>))
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25328r514654_chk'
  tag severity: 'medium'
  tag gid: 'V-223655'
  tag rid: 'SV-223655r604139_rule'
  tag stig_id: 'RACF-ES-000070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25316r514655_fix'
  tag 'documentable'
  tag legacy: ['V-98015', 'SV-107119']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
