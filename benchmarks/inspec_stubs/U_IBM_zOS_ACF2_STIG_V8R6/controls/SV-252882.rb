control 'SV-252882' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Configuration parameters must be correctly specified.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) product has the ability to use privileged functions and/or have access to sensitive data. Failure to properly configure parameter values could potentially the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the CSFPRMxx member in the logical PARMLIB concatenation.

If the configuration parameters are specified as follows, this is not a finding. 

REASONCODES(ICSF) 
COMPAT(NO) 
SSM(NO) 
SSM can be dynamically set by defining the CSF.SSM.ENABLE SAF profile within the XFACILIT resource
Class. If this profile is not limited to authorized personnel this is a finding.
CHECKAUTH(YES) 
FIPSMODE(YES,FAIL(YES))
AUDITKEYLIFECKDS (TOKEN(YES),LABEL(YES)).
AUDITKEYLIFEPKDS (TOKEN(YES),LABEL(YES)).
AUDITKEYLIFETKDS (TOKENOBJ(YES),SESSIONOBJ(YES)).
AUDITKEYUSGCKDS (TOKEN(YES),LABEL(YES),INTERVAL(n)).
AUDITKEYUSGPKDS (TOKEN(YES),LABEL(YES),INTERVAL(n)).
AUDITPKCS11USG (TOKENOBJ(YES),SESSIONOBJ(YES),NOKEY(YES),INTERVAL(n)).

DEFAULTWRAP - This parameter can be determined by the site. ENHANCED wrapping specifies the new X9.24 compliant CBC wrapping is used.  
If DEFAULTWRAP is not specified, the default wrapping method will be ORIGINAL for both internal and external tokens. Starting with ICSF FMID HCR77C0, the value for this option can be updated without restarting ICSF by using either the SETICSF command or the ICSF Multi-Purpose service. If this access is not restricted to appropriate personnel, this is a finding.

Note: Other options may be site-defined.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control options. Develop a plan of action to implement the control options for CSFPRMxx as specified below:

REASONCODES(ICSF) 
COMPAT(NO) 
SSM(NO) 
SSM can be dynamically set by defining the CSF.SSM.ENABLE SAF profile within the XFACILIT resource class. This profile must limited to authorized personnel.

CHECKAUTH(YES) 
FIPSMODE(YES,FAIL(YES))
AUDITKEYLIFECKDS (TOKEN(YES),LABEL(YES)).
AUDITKEYLIFEPKDS (TOKEN(YES),LABEL(YES)).
AUDITKEYLIFETKDS (TOKENOBJ(YES),SESSIONOBJ(YES)).
AUDITKEYUSGCKDS (TOKEN(YES),LABEL(YES),INTERVAL(n)).
AUDITKEYUSGPKDS (TOKEN(YES),LABEL(YES),INTERVAL(n)).
AUDITPKCS11USG (TOKENOBJ(YES),SESSIONOBJ(YES),NOKEY(YES),INTERVAL(n)).

DEFAULTWRAP - This parameter can be determined by the site. ENHANCED wrapping specifies the new X9.24 compliant CBC wrapping is used.  
If DEFAULTWRAP is not specified, the default wrapping method will be ORIGINAL for both internal and external tokens. Starting with ICSF FMID HCR77C0, the value for this option can be updated without restarting ICSF by using either the SETICSF command or the ICSF Multi-Purpose service. This access must be restricted to appropriate personnel.

Note: Other options may be site-defined.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-56338r822533_chk'
  tag severity: 'medium'
  tag gid: 'V-252882'
  tag rid: 'SV-252882r822535_rule'
  tag stig_id: 'ACF2-IC-000010'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-56288r822534_fix'
  tag 'documentable'
  tag legacy: ['V-18014', 'SV-95665']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
