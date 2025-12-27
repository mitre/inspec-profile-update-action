control 'SV-224023' do
  title 'The IBM z/OS SNTP daemon (SNTPD) must be active.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'From UNIX System Services ISPF Shell navigate to ribbon select tools.
Select option 1 - Work with Processes.

If SNTP Daemon (SNTPD) is not active, this is a finding.'
  desc 'fix', 'Obtain a copy of this sample procedure from SEZAINST and store it in one of your PROCLIB concatenation data sets.

Perform the following step to start SNTPD as a procedure:
Invoke the procedure using the system operator start command. The following sample, SEZAINST(SNTPD), shows how to start SNTPD as a procedure:
//*
//* Sample procedure for the Simple Network Time Protocol (SNTP)
//*
//* z/OS Communications Server Version 1 Release 13
//* SMP/E Distribution Name: SEZAINST(EZASNPRO)
//*
//* Copyright: Licensed Materials - Property of IBM
//* 5650-ZOS
//* Copyright IBM Corp. 2002, 2015
//*
//* Status: CSV2R2
//*
//SNTPD EXEC PGM=SNTPD,REGION=4096K,TIME=NOLIMIT,
// PARM=’/ -d’
//SYSPRINT DD SYSOUT=*,DCB=(RECFM=F,LRECL=132,BLKSIZE=132)
//SYSIN DD DUMMY
//SYSERR DD SYSOUT=*
//SYSOUT DD SYSOUT=*,DCB=(RECFM=F,LRECL=132,BLKSIZE=132)
//CEEDUMP DD SYSOUT=*
//SYSABEND DD SYSOUT=*'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25696r516468_chk'
  tag severity: 'medium'
  tag gid: 'V-224023'
  tag rid: 'SV-224023r561402_rule'
  tag stig_id: 'TSS0-OS-000270'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-25684r516469_fix'
  tag 'documentable'
  tag legacy: ['V-98755', 'SV-107859']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
