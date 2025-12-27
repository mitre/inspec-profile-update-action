control 'SV-223787' do
  title 'IBM z/OS must not have duplicated sensitive utilities and/or programs existing in APF libraries.'
  desc 'Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.'
  desc 'check', 'From an ISPF Command line enter:
TSO ISRDDN APF

An APF List results

On the command line enter:
DUPlicates (make sure there is appropriate access; if there is not you may receive insufficient access errors)

If any of the list of Sensitive Utilities exist in the duplicate APF modules return, this is a finding.

The following list contains Sensitive Utilities that will be checked.

AHLGTF AMASPZAP AMAZAP AMDIOCP AMZIOCP
BLSROPTR CSQJU003 CSQJU004 CSQUCVX CSQUTIL
CSQ1LOGP DEBE DITTO FDRZAPOP GIMSMP
HHLGTF ICKDSF ICPIOCP IDCSC01 IEHINITT
IFASMFDP IGWSPZAP IHLGTF IMASPZAP IND$FILE
IOPIOCP IXPIOCP IYPIOCP IZPIOCP WHOIS
L052INIT TMSCOPY TMSFORMT TMSLBLPR TMSMULV
TMSREMOV TMSTPNIT TMSUDSNB'
  desc 'fix', 'Review and ensure that duplicate sensitive utility(ies) and/or program(s) do not exist in APF-authorized libraries. Identify all versions of the sensitive utilities contained in APF-authorized libraries listed in the above check. In cases where duplicates exist, ensure no exposure has been created and written justification has been filed with the ISSO.

Comparisons among all the APF libraries will be done to ensure that an exposure is not created by the existence of identically named modules. Address any sensitive utility concerns so that the function can be restricted as required.'
  impact 0.3
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25460r515049_chk'
  tag severity: 'low'
  tag gid: 'V-223787'
  tag rid: 'SV-223787r604139_rule'
  tag stig_id: 'RACF-OS-000310'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-25448r515050_fix'
  tag 'documentable'
  tag legacy: ['V-98281', 'SV-107385']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
