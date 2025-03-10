control 'SV-224264' do
  title 'CA 1 Tape Management external security options must be specified properly.'
  desc 'CA 1 Tape Management offers multiple external security interfaces that are controlled by parameters specified in TMOOPT00.  These interfaces provide security controls for several CA 1 system and user functions.  Without proper controls of these sensitive functions, the integrity of the CA 1 Tape Management System and the confidentiality of data stored on tape volumes may be compromised.'
  desc 'check', 'Refer to the following report produced by the z/OS Data Collection:

-       CA1RPT(TMSSTATS)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-       PDI(ZCA10040)

CA 1 external security utilizing ACF2 is accomplished in the manner described in this section.

NOTE:       The TMOOPTxx member is specified in the TMOSYSxx member in the data set allocated by the TMSPARM DD statement in the TMSINIT STC. By default, the suffix 00 is used for these members. However, overrides can be specified by PARM value(s) on the EXEC statement in the TMSINIT STC and/or in the TMOSYSxx member.

Review the options and values of the below CA 1 parameters. If the options are set to the specified value, this is not a finding.

CA 1 SECURITY OPTIONS - ACF2
Option       Value
BATCH       YES obsolete as of r12.0
CATSEC       NO obsolete as of r12.0
CMD       YES
CREATE      see Note 1
DSNB       YES
FUNC       YES see Note 2
OCEOV       NO see Note 3
PMASK       Do not specify or change
PSWD       YES
SCRTCH       NO
SECWTO       YES
UNDEF       FAIL
UX0AUPD       NO see Note 4
YSVC       YES

Note 1       The CREATE parameter defines the level of access that is required to create a data set on tape. The default value is UPDATE. However, the vendor recommends the value be set to CREATE if you are running CA Top Secret or ACF2 and ALTER if you are running RACF.

Note 2       The FUNC option provides supplementary security for BLP access. The tape label bypass privilege must still be specified in the ACF2 user LID record to allow access to BLP processing.

Note 3       The CA 1 security option, OCEOV, is set to NO because ACF2 obtains control of data set OPEN/CLOSE processing before the CA 1 intercept. The vendor recommends that the first security call be used and that this CA 1 control option be turned OFF. Therefore, TAPEDSN must be specified in the OPTS option in the ACF2 GSO record.

Note 4       The UX0AUPD will specify YES only if you alter the fields in the TMC and the TMSUXxA (for r11.5 and below) or TMSXITA (for r12.0 and above) is changed.'
  desc 'fix', 'The systems programmer/IAO will ensure that the CA 1 external security options are specified in accordance with the ACP being used.  CA 1 Tape Management ACP security interfaces are controlled by options coded in the TMOOPTxx member identified in the TMOSYSxx member of the data set allocated by the TMSPARM DD statement in the TMSINIT STC.  The specific required option settings are dependent on the ACP in use on the system.

CA 1 SECURITY OPTIONS - ACF2
Option	Value
BATCH	YES obsolete as of r12.0
CATSEC	NO obsolete as of r12.0
CMD	YES
CREATE	see note 1
DSNB	YES
FUNC	YES see note 2
OCEOV	NO see note 3
PMASK	Do not specify or change
PSWD	YES
SCRTCH	NO
SECWTO	YES
UNDEF	FAIL
UX0AUPD	NO see note 4
YSVC	YES

Note 1       The CREATE parameter defines the level of access that is required to create a data set on tape. The default value is UPDATE. However, the vendor recommends the value be set to CREATE if you are running CA Top Secret or ACF2 and ALTER if you are running RACF.

Note 2	The FUNC option provides supplementary security for BLP access.  The tape label bypass privilege must still be specified in the ACF2 user LID record to allow access to BLP processing.

Note 3	The CA 1 security option, OCEOV, is set to NO because ACF2 obtains control of data set OPEN/CLOSE processing before the CA 1 intercept.  The vendor recommends that the first security call be used and that this CA 1 control option be turned OFF.  Therefore, TAPEDSN must be specified in the OPTS option in the ACF2 GSO record.

Note 4	The UX0AUPD will specify YES only if you alter the fields in the TMC and the TMSUXxA (for r11.5 and below) or TMSXITA (for r12.0 and above) is changed.'
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for ACF2'
  tag check_id: 'C-25937r519476_chk'
  tag severity: 'medium'
  tag gid: 'V-224264'
  tag rid: 'SV-224264r519478_rule'
  tag stig_id: 'ZCA1A040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25925r519477_fix'
  tag 'documentable'
  tag legacy: ['SV-40100', 'V-18014']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
