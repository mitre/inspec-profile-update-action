control 'SV-223469' do
  title 'IBM z/OS TSO GSO record values must be set to the values specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ACF Command screen enter:
SET CONTROL(GSO)
LIST TSO

If the GSO TSO record values conform to the following requirements, this is not a finding.

ACCOUNT(1)
BYPASS(#)
CHAR(BS)
CMDLIST()
NOIKJEFLD1
LINE(ATTN)
LOGONCK
PERFORM(0)
PROC(site defined)
NOQLOGON
REGION(site defined)
SUBCLSS()
SUBHOLD()
SUBMSG()
TIME(0)
TSOSOUT(A)
UNIT(SYSDA)
WAITIME(1-60)'
  desc 'fix', 'Configure the GSO TSO record values to conform to the following requirements.

ACCOUNT(1)
BYPASS(#)
CHAR(BS)
CMDLIST()
NOIKJEFLD1
LINE(ATTN)
LOGONCK
PERFORM(0)
PROC(site defined)
NOQLOGON
REGION(site defined)
SUBCLSS()
SUBHOLD()
SUBMSGC()
TIME(0)
TSOSOUT(A)
UNIT(SYSDA)
WAITIME(1-60)

Example:
SET C(GSO)
INSERT TSO ACCOUNT(1) BYPASS(#) CHAR(BS) CMDLIST() NOIKJEFLD1 LINE(ATTN) LOGONCK PERFORM(0) PROC(IKJACCNT) NOQLOGON REGION(4,096) SUBCLSS() SUBHOLD() SUBMSGC() TIME(0) TSOGNAME() TSOSOUT(A) UNIT(SYSDA) WAITIME(60) 

F ACF2,REFRESH(TSO)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25142r504525_chk'
  tag severity: 'medium'
  tag gid: 'V-223469'
  tag rid: 'SV-223469r533198_rule'
  tag stig_id: 'ACF2-ES-000510'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25130r504526_fix'
  tag 'documentable'
  tag legacy: ['V-97637', 'SV-106741']
  tag cci: ['CCI-000366', 'CCI-001133']
  tag nist: ['CM-6 b', 'SC-10']
end
