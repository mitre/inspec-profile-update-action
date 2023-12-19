control 'SV-219777' do
  title 'Processes (services, applications, etc.) that connect to the DBMS independently of individual users, must use valid, current DoD-issued PKI certificates for authentication to the DBMS.'
  desc 'Just as individual users must be authenticated, and just as they must use PKI-based authentication, so must any processes that connect to the DBMS.

The DoD standard for authentication of a process or device communicating with another process or device is the presentation of a valid, current, DoD-issued Public Key Infrastructure (PKI) certificate that has previously been verified as Trusted by an administrator of the other process or device.

This applies both to processes that run on the same server as the DBMS and to processes running on other computers.

The Oracle-supplied super-user account, SYS, is an exception.  It cannot currently use certificate-based authentication.  For this reason among others, use of SYS should be restricted to where it is truly needed.'
  desc 'check', 'Review configuration to confirm that accounts used by processes to connect to the DBMS are authenticated using valid, current DoD-issued PKI certificates.

If any such account, other than SYS, is not certificate-based, this is a finding.'
  desc 'fix', 'For each such account, use DoD certificate-based authentication.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21502r307180_chk'
  tag severity: 'medium'
  tag gid: 'V-219777'
  tag rid: 'SV-219777r397600_rule'
  tag stig_id: 'O112-C2-015501'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-21501r307181_fix'
  tag 'documentable'
  tag legacy: ['SV-67497', 'V-53281']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
