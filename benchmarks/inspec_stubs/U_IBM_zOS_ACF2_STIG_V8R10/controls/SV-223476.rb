control 'SV-223476' do
  title 'The CA-ACF2 GSO OPTS record value must be properly specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ACF Command enter:
SET CONTROL(GSO)
LIST OPTS

If the GSO OPTS record values conform to the following requirements, this is not a finding.

BLPLOG
NOCMDREC
CONSOLE(NOROLL)
CPUTIME(LOCAL)
DATE(MDY)
NODDB
DFTLID()
DFTSTC()
INFOLIST(none | AUDIT | SECURITY | SECURITY, AUDIT)
JOBCK
MAXVIO(10)
NOTIFY
RPTSCOPE
SHRDASD
STAMPSMF
STC
TAPEDSN
TEMPDSN
NOUADS
NOVTAMOPEN'
  desc 'fix', 'Define the global options available to the system.

BLPLOG
NOCMDREC
CONSOLE(NOROLL)
CPUTIME(LOCAL)
DATE(MDY)
NODDB
DFTLID()
DFTSTC()
INFOLIST(none | AUDIT | SECURITY | SECURITY, AUDIT)
JOBCK
MAXVIO(10)
NOTIFY
RPTSCOPE
SHRDASD
STAMPSMF
STC
TAPEDSN
TEMPDSN
NOUADS
NOVTAMOPEN

Example:
SET C(GSO)
INSERT OPTS BLPLOG NOCMDREC CONSOLE(NOROLL) CPUTIME(LOCAL) DATE(MDY) NODDB DFTLID() DFTSTC() INFOLIST(SECURITY, AUDIT) JOBCK MAXVIO(10)
MODE(ABORT) NOTIFY RPTSCOPE SHRDASD STAMPSMF STC TAPEDSN TEMPDSN NOUADS NOVTAMOPEN

F ACF2,REFRESH(OPTS)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25149r695411_chk'
  tag severity: 'medium'
  tag gid: 'V-223476'
  tag rid: 'SV-223476r695413_rule'
  tag stig_id: 'ACF2-ES-000580'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25137r695412_fix'
  tag 'documentable'
  tag legacy: ['V-97651', 'SV-106755']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
