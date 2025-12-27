control 'SV-223638' do
  title 'IBM z/OS Attributes of UNIX user accounts used for account modeling must be defined in accordance with security requirements.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'If this is a Classified system, this is Not Applicable.

From an ACF2 command line enter:
SET CONTROL(GSO)
SHOW UNIXOPTS

Alternately:
Refer to the following report produced by the ACF2 Data Collection:
- ACF2CMDS.RPT(ACFGSO)
- ACF2CMDS.RPT(OMVSUSER)

Note: This check applies to any user identifier (LOGONID) used to model OMVS access on the mainframe. This includes any DFTUSER; MODLUSER and BPX.UNIQUE.USER. If MODLUSER is specified then UNIQUSER must be specified.

If DFTUSER or MODLUSER is not defined in the UNIXOPTS record, this is not a finding.

If ALL user identifiers (LOGONID) defined to DFTUSER or MODLUSER. or BPX.UNIQUE.USER user account is defined as follows, this is not a finding:

A non-writable HOME directory:
Shell program specified as “/bin/echo” or “/bin/false”

Note: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  desc 'fix', 'Define DFTUSER or MODLUSER or BPX.UNIQUE.USER user account to be defined as follows:

A non-writable HOME directory:
Shell program specified as "/bin/echo" or "/bin/false"

Note: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).

Example:
SET PROFILE(USER) DIV(OMVS)
LIST OMVS

INSERT OMVS HOME(/) OMVSPGM(/bin/false) UID(0)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25311r504869_chk'
  tag severity: 'medium'
  tag gid: 'V-223638'
  tag rid: 'SV-223638r533198_rule'
  tag stig_id: 'ACF2-US-000230'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25299r504870_fix'
  tag 'documentable'
  tag legacy: ['SV-107085', 'V-97981']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
