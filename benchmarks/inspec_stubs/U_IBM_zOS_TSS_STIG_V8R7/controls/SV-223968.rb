control 'SV-223968' do
  title 'CA-TSS MSCA ACID must perform security administration only.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(ACIDS) DATA(ALL,PA) TYPE(SCA)

If the MSCA ACID has access limited to performing security administration functions only, this is not a finding.

Below is an example of allowed setup for MSCA account and authorities. "MSCA" as the Accessorid, is merely an example here, which is site determined. List is not all inclusive. The primary SCA for the domain will be listed within the "NAME" field since they are responsible for the MSCA ACID.

ACCESSORID = MSCA NAME = "primary SCA"
TYPE = MASTER
FACILITY = BATCH 
PROFILES = SECURID
ATTRIBUTES = AUDIT,CONSOLE,NOATS 
data set = %. *.
data set = ***** +.
VOLUMES = *(G)
XA data set = SYS3.TSS.BACKUP
ACCESS = UPDATE
ACTION = AUDIT 
----------- ADMINISTRATION AUTHORITIES
RESOURCE = *ALL*
ACCESS = ALL
ACID = *ALL*
FACILITIES = *ALL*
LIST DATA = *ALL*,PROFILES,PASSWORD,SESSKEY
MISC1 = *ALL*
MISC2 = *ALL*
MISC4 = *ALL*
MISC8 = *ALL*
MISC9 = *ALL*

NOTE 1: Update access to the backup security database is required by the MSCA account anytime the ISSO needs to run/submit the TSS Utility called TSSFAR. MSCA account may from time to time be required to have additional access for the period of project such as Extending the Security Database.

NOTE 2: MSCA account must be used for such items as: TSSFAR, EXTENDING Security Database, creating SCA/LSCA accounts, working with LSCA accounts (scoping, admin rights, etc.). Most often the ISSO staff will utilize their normal SCA account. The MSCA account will not be anyone’s primary security administrative account.'
  desc 'fix', 'The ISSO will review the MSCA and ensure access granted is limited to those resources necessary to support the security administration function. Evaluate the impact of correcting the deficiency and develop a plan of action to implement the changes.

Below is an example of allowed setup for MSCA account and authorities. "MSCA" as the Accessorid, is merely an example here, which is site determined. List is not all inclusive. The primary SCA for the domain will be listed within the "NAME" field since they are responsible for the MSCA ACID.

ACCESSORID = MSCA NAME = "primary SCA"
TYPE = MASTER
FACILITY = BATCH 
PROFILES = SECURID
ATTRIBUTES = AUDIT,CONSOLE,NOATS 
data set = %. *.
data set = ***** +.
VOLUMES = *(G)
XA data set = SYS3.TSS.BACKUP
ACCESS = UPDATE
ACTION = AUDIT 
----------- ADMINISTRATION AUTHORITIES
RESOURCE = *ALL*
ACCESS = ALL
ACID = *ALL*
FACILITIES = *ALL*
LIST DATA = *ALL*,PROFILES,PASSWORD,SESSKEY
MISC1 = *ALL*
MISC2 = *ALL*
MISC4 = *ALL*
MISC8 = *ALL*
MISC9 = *ALL*

NOTE 1: Update access to the backup security database is required by the MSCA account anytime the ISSO needs to run/submit the TSS Utility called TSSFAR. MSCA account may from time to time be required to have additional access for the period of project such as Extending the Security Database.

NOTE 2: MSCA account must be used for such items as: TSSFAR, EXTENDING Security Database, creating SCA/LSCA accounts, working with LSCA accounts (scoping, admin rights, etc). Most often the ISSO staff will utilize their normal SCA account. The MSCA account will not be anyone’s primary security administrative account.

NOTE 3: MSCA account must be limited in access, to least privileged access of resources required to function.

NOTE 4: If running Quest NC-Pass, validate in ZNCP0020 that the MSCA ACID has the FACILITY of NCPASS and SECURID resource in the ABSTRACT resource class.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25641r516303_chk'
  tag severity: 'medium'
  tag gid: 'V-223968'
  tag rid: 'SV-223968r856105_rule'
  tag stig_id: 'TSS0-ES-000950'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25629r516304_fix'
  tag 'documentable'
  tag legacy: ['SV-107747', 'V-98643']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
