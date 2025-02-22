control 'SV-224304' do
  title 'CICS System Initialization Table (SIT) parameter values must be specified in accordance with proper security requirements.'
  desc 'The CICS SIT is used to define system operation and configuration parameters of a CICS system. Several of these parameters control the security within a CICS region. Failure to code the appropriate values could result in unexpected operations and degraded security. This exposure may result in unauthorized access impacting the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', "Refer to the following report produced by the z/OS Data Collection:

- EXAM.RPT(CICSPROC)

Refer to the following report produced by the CICS Data Collection:

- CICS.RPT(DFHSITxx)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

Refer to the CICS region SYSLOG - (Alternate source of SIT parameters) be sure to process DFHSIT based on the order specified. The system initialization parameters are processed in the following order, with later system initialization parameter values overriding those specified earlier. CICS system initialization parameters are specified in the following ways:

- In the system initialization table, loaded from a library in the STEPLIB concatenation of the CICS startup procedure.
- In the PARM parameter of the EXEC PGM=DFHSIP statement of the CICS startup procedure.
- In the SYSIN data set defined in the startup procedure (but only if SYSIN is coded in the PARM parameter).
- In the ACF2PARM data set defined in the startup procedure.

Ensure the following CICS System Initialization Table (SIT) parameter settings are specified for each CICS region. If the following guidance is true, this is not a finding.

___ SEC=YES - If SEC is not coded in the CICS region startup JCL, go to offset x'117' from the beginning on the SIT dump (record sequence number - 6) for a length of 1. This is the security byte flag. Below is the hex and bit settings for this flag.

X'80' EQU B'10000000' External Security Requested

___ DFLTUSER=<parameter> - If DFLTUSER is not coded in the CICS region startup JCL, go to offset x'118' from the beginning on the SIT dump (record sequence number - 6) for a length of 8 bytes. The value will be the CICS default userid. ACF2PARM overrides the CICS SIT DFLTUSER parameter value with the logonid supplied in the ACF2PARM DEFAULT TERMINAL= parameter.

___ XUSER=YES - If XUSER is not coded in the CICS region startup JCL, go to offset x'117' from the beginning on the SIT dump (record sequence number - 6) for a length of 1. This is the security byte flag. Below is the hex and bit settings for this flag.

X'04' EQU B'00000100' Surrogate User Checking required

The CICS interface now controls this DFHSIT keyword via the INITIAL XUSER= initialization parameter. The CICS interface dynamically sets this DFHSIT setting during initialization processing using the value specified via the ACF2PARM parameter file. This overrides any value specified by the CICS systems programmer via the CICS SYSIN file, execution parameter overrides, or the DFHSIT table itself so that it is the security administrator and not the CICS systems programmer that controls surrogate userid checking

___ SNSCOPE=NONE|CICS|MVSIMAGE|SYSPLEX - If SNSCOPE is not coded in the CICS region startup JCL, go to offset x'124' from the beginning on the SIT dump (record sequence number - 6) for a length of 1. This is the signon scope byte flag. Ensure that users cannot sign on to more than one CICS production region within the scope of a single CICS region, a single z/OS image, or a sysplex. Below are listed the hex and bit settings for this flag:

X'01' EQU 1 SIGNON SCOPE = NONE
X'02' EQU 2 SIGNON SCOPE = CICS
X'03' EQU 3 SIGNON SCOPE = MVSIMAGE
X'04' EQU 4 SIGNON SCOPE = SYSPLEX

NOTE: SNSCOPE=NONE is only allowed with test/development regions."
  desc 'fix', "Ensure that CICS System Initialization Table (SIT) parameter values are specified using the following guidance.

The system initialization parameters are processed in the following order, with later system initialization parameter values overriding those specified earlier. CICS system initialization parameters are specified in the following ways:

- In the system initialization table, loaded from a library in the STEPLIB concatenation of the CICS startup procedure.
- In the PARM parameter of the EXEC PGM=DFHSIP statement of the CICS startup procedure.
- In the SYSIN data set defined in the startup procedure (but only if SYSIN is coded in the PARM parameter).
- In the ACF2PARM data set defined in the startup procedure.

Ensure the following CICS System Initialization Table (SIT) parameter settings are specified for each CICS region:

SEC=YES - If SEC is not coded in the CICS region startup JCL, go to offset x'117' from the beginning on the SIT dump (record sequence number - 6) for a length of 1. This is the security byte flag. Below are listed the hex and bit settings for this flag. 

X'80' EQU B'10000000' External Security Requested <<===
X'40' EQU B'01000000' Resource Prefix Required
X'10' EQU B'00010000' RACLIST class APPCLU required
X'08' EQU B'00001000' ESM INSTLN data is required
X'04' EQU B'00000100' Surrogate User Checking required
X'02' EQU B'00000010' Always enact resource check
X'01' EQU B'00000001' Always enact command check

DFLTUSER=<parameter> - If DFLTUSER is not coded in the CICS region startup JCL, go to offset x'118' from the beginning on the SIT dump (record sequence number - 6) for a length of 8 bytes. The value will be the CICS default userid.

XUSER=YES - If XUSER is not coded in the CICS region startup JCL, go to offset x'117' from the beginning on the SIT dump (record sequence number - 6) for a length of 1. This is the security byte flag. Below are listed the hex and bit settings for this flag.

X'80' EQU B'10000000' External Security Requested
X'40' EQU B'01000000' Resource Prefix Required
X'10' EQU B'00010000' RACLIST class APPCLU required
X'08' EQU B'00001000' ESM INSTLN data is required
X'04' EQU B'00000100' Surrogate User Checking required <<===
X'02' EQU B'00000010' Always enact resource check
X'01' EQU B'00000001' Always enact command check

SNSCOPE=NONE|CICS|MVSIMAGE|SYSPLEX - If SNSCOPE is not coded in the CICS region startup JCL, go to offset x'124' from the beginning on the SIT dump (record sequence number - 6) for a length of 1. This is the signon scope byte flag. Ensure that users cannot sign on to more than one CICS production region within the scope of a single CICS region, a single z/OS image, or a sysplex. Below are listed the hex and bit settings for this flag:

X'01' EQU 1 SIGNON SCOPE = NONE
X'02' EQU 2 SIGNON SCOPE = CICS
X'03' EQU 3 SIGNON SCOPE = MVSIMAGE
X'04' EQU 4 SIGNON SCOPE = SYSPLEX

NOTE: SNSCOPE=NONE is only allowed with test/development regions."
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25981r868096_chk'
  tag severity: 'medium'
  tag gid: 'V-224304'
  tag rid: 'SV-224304r868098_rule'
  tag stig_id: 'ZCIC0030'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-25969r868097_fix'
  tag 'documentable'
  tag legacy: ['SV-302', 'V-302']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
