control 'SV-223997' do
  title 'Duplicated IBM z/OS sensitive utilities and/or programs must not exist in APF libraries.'
  desc 'Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.'
  desc 'check', 'From an ISPF Command line enter:
TSO ISRDDN APF

An APF List results. On the Command line enter:
DUPlicates (Make sure there is appropriate access. If there is not, you may receive insufficient access errors.)

If any of the list of Sensitive Utilities exist in the duplicate APF modules returned, this is a finding.

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
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25670r516390_chk'
  tag severity: 'medium'
  tag gid: 'V-223997'
  tag rid: 'SV-223997r561402_rule'
  tag stig_id: 'TSS0-OS-000010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-25658r516391_fix'
  tag 'documentable'
  tag legacy: ['SV-107805', 'V-98701']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
