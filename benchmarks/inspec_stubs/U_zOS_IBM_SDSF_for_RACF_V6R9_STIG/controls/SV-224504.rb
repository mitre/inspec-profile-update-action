control 'SV-224504' do
  title 'IBM System Display and Search Facility (SDSF) Configuration parameters must be correctly specified.'
  desc 'IBM System Display and Search Facility (SDSF) ISFPARMS defines global options, panel formats, and security for SDSF.  Failure to properly specify these parameter values could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', 'Refer to the JCL procedure libraries defined to JES2 for the SDSF started task member for SDSFPARM DD statement.

Refer to the ISRPRMxx members in the logical PARMLIB concatenation.

Refer to the results of the “F SDSF,D” command. Where SDSF should specify the SDSF started task name.

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZISF0040)

Ensure the following Group Parameters are specified or not specified in the GROUP statements defined in the ISFPARMS members. If the following guidance is true, this is not a finding.

For each GROUP statement:
AUPDT(0)
AUTH will not be specified
CMDAUTH will not be specified
CMDLEV will not be specified
DSPAUTH will not be specified
NAME a value will be specified for the NAME'
  desc 'fix', 'Ensure  that the following Group function parameters appear and/or do not appear in ISFPARMS.

For each GROUP statement:
AUPDT(0)
AUTH will not be specified
CMDAUTH will not be specified
CMDLEV will not be specified
DSPAUTH will not be specified
NAME a value will be specified for the NAME

The ISFPARMS GROUP statement defines user groups and their characteristics. Some of these characteristics include access authorization to SDSF functions and commands. Access to these functions and commands will be controlled using SAF resources. The use of the SAF interface is consistent with the DOD requirement to control all products within the operating system using the ACP. To ensure SAF security is always in effect, authorizations to SDSF functions and commands should not be defined in ISFPARMS DD statement in the SDSF JCL member.'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for RACF'
  tag check_id: 'C-26187r520361_chk'
  tag severity: 'medium'
  tag gid: 'V-224504'
  tag rid: 'SV-224504r520363_rule'
  tag stig_id: 'ZISF0040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26175r520362_fix'
  tag 'documentable'
  tag legacy: ['V-18014', 'SV-40746']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
