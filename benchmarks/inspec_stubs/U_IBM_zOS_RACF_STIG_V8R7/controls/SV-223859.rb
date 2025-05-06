control 'SV-223859' do
  title 'The IBM z/OS user account for the UNIX kernel (OMVS) must be properly defined to the security database.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.'
  desc 'check', 'If OMVS userid is defined to the ESM as follows, this is not a finding.

No access to interactive on-line facilities (e.g., TSO, CICS, etc.)
Default group specified as OMVSGRP or STCOMVS
UID(0)
HOME directory specified as “/”
Shell program specified as “/bin/sh”'
  desc 'fix', 'Define OMVS userid to the ESM as specified below:

No access to interactive on-line facilities (e.g., TSO, CICS, etc.)
Default group specified as OMVSGRP or STCOMVS
UID(0)
HOME directory specified as “/”
Shell program specified as “/bin/sh”'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25532r515265_chk'
  tag severity: 'medium'
  tag gid: 'V-223859'
  tag rid: 'SV-223859r604139_rule'
  tag stig_id: 'RACF-US-000220'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25520r515266_fix'
  tag 'documentable'
  tag legacy: ['V-98425', 'SV-107529']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
