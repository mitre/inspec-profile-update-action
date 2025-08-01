control 'SV-225575' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Configuration parameters must be correctly specified.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) product has the ability to use privileged functions and/or have access to sensitive data. Failure to properly configure parameter values could potentially the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the CSFPRMxx member in the logical PARMLIB concatenation.

If the configuration parameters are specified as follows this is not a finding. 

REASONCODES(ICSF) 
COMPAT(NO) 
SSM(YES) 
CHECKAUTH(YES) 
FIPSMODE(YES,FAIL(YES))
AUDITKEYLIFECKDS (TOKEN(YES),LABEL(YES)).
AUDITKEYLIFEPKDS (TOKEN(YES),LABEL(YES)).
AUDITKEYLIFETKDS (TOKENOBJ(YES),SESSIONOBJ(YES)).
AUDITKEYUSGCKDS (TOKEN(YES),LABEL(YES),INTERVAL(n)).
AUDITKEYUSGPKDS (TOKEN(YES),LABEL(YES),INTERVAL(n)).
AUDITPKCS11USG (TOKENOBJ(YES),SESSIONOBJ(YES),NOKEY(YES),INTERVAL(n)).

DEFAULTWRAP should not be specified.

Note: Other options may be site defined.'
  desc 'fix', 'Refer to the CSFPRMxx member in the logical PARMLIB concatenation.

If the configuration parameters are specified as follows this is not a finding. 

REASONCODES(ICSF) 
COMPAT(NO) 
SSM(YES) 
CHECKAUTH(YES) 
FIPSMODE(YES,FAIL(YES))
AUDITKEYLIFECKDS (TOKEN(YES),LABEL(YES)).
AUDITKEYLIFEPKDS (TOKEN(YES),LABEL(YES)).
AUDITKEYLIFETKDS (TOKENOBJ(YES),SESSIONOBJ(YES)).
AUDITKEYUSGCKDS (TOKEN(YES),LABEL(YES),INTERVAL(n)).
AUDITKEYUSGPKDS (TOKEN(YES),LABEL(YES),INTERVAL(n)).
AUDITPKCS11USG (TOKENOBJ(YES),SESSIONOBJ(YES),NOKEY(YES),INTERVAL(n)).

DEFAULTWRAP should not be specified.

Note: Other options may be site defined.'
  impact 0.5
  ref 'DPMS Target zOS ICSF for TSS'
  tag check_id: 'C-27274r695251_chk'
  tag severity: 'medium'
  tag gid: 'V-225575'
  tag rid: 'SV-225575r695253_rule'
  tag stig_id: 'ZICS0040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-27262r695252_fix'
  tag 'documentable'
  tag legacy: ['V-18014', 'SV-95665']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
