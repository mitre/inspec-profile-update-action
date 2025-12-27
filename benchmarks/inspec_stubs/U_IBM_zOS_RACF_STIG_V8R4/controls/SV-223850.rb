control 'SV-223850' do
  title 'The IBM RACF classes required to properly secure the z/OS UNIX environment must be ACTIVE.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts list

If the ACTIVE CLASSES list includes entries for the FACILITY, SURROGAT, and UNIXPRIV resource classes, this is not a finding.

If either of the above resource classes is missing, this is a finding.'
  desc 'fix', 'Define the ACTIVE CLASS Parameter in SETROPTS to include the FACILITY, SURROGAT and UNIXPRIV resource classes.

EXAMPLES:
SETR CLASSACT(FACILITY SURROGAT UNIXPRIV) 

SETR GENERIC(FACILITY SURROGAT UNIXPRIV)
SETR GENCMD(FACILITY SURROGAT UNIXPRIV)

SETR RACL(FACILITY SURROGAT UNIXPRIV)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25523r515238_chk'
  tag severity: 'medium'
  tag gid: 'V-223850'
  tag rid: 'SV-223850r604139_rule'
  tag stig_id: 'RACF-US-000130'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-25511r515239_fix'
  tag 'documentable'
  tag legacy: ['SV-107511', 'V-98407']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
