control 'SV-220293' do
  title 'Processes (services, applications, etc.) that connect to the DBMS independently of individual users, must use valid, current DoD approved PKI certificates for authentication to the DBMS.'
  desc 'Just as individual users must be authenticated, and just as they must use PKI-based authentication, so must any processes that connect to the DBMS.

The DoD standard for authentication of a process or device communicating with another process or device is the presentation of a valid, current, DoD-issued Public Key Infrastructure (PKI) certificate that has previously been verified as Trusted by an administrator of the other process or device.

This applies both to processes that run on the same server as the DBMS and to processes running on other computers.

The Oracle-supplied accounts, SYS, SYSBACKUP, SYSDG, and SYSKM, are exceptions.  These cannot currently use certificate-based authentication.  For this reason among others, use of these accounts should be restricted to where it is truly needed.'
  desc 'check', 'Review configuration to confirm that accounts used by processes to connect to the DBMS are authenticated using valid, current DoD approved PKI certificates.

If any such account (other than SYS, SYSBACKUP, SYSDG, and SYSKM) is not certificate-based, this is a finding.'
  desc 'fix', 'For each such account, use DoD certificate-based authentication.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22008r666958_chk'
  tag severity: 'medium'
  tag gid: 'V-220293'
  tag rid: 'SV-220293r666959_rule'
  tag stig_id: 'O121-C2-015501'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-22000r392011_fix'
  tag 'documentable'
  tag legacy: ['SV-76235', 'V-61745']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
