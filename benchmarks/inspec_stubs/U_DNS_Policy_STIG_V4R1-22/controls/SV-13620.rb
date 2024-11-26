control 'SV-13620' do
  title %q(The SA has not subscribed to ISC's mailing list "bind announce" for updates on vulnerabilities and software notifications.)
  desc 'Whether running the latest version or software or an earlier version, the administrator should be aware of the vulnerabilities, exploits, security fixes, and patches for the version that is in operation in the enterprise.'
  desc 'check', 'If the site is using BIND, interview the SA to determine if they have subscribed to ISC’s mailing list called “bind-announce” (information on the Internet at ttp://www.isc.org/sw/bind/bind-lists.php) for vulnerabilities and software notifications.Note:  This check only applies to Windows and Unix systems running BIND.  It should be marked Not Applicable for those not running BIND.

If the site is using BIND, interview the SA to determine if they have subscribed to ISC’s mailing list called “bind-announce” (information on the Internet at http://www.isc.org/sw/bind/bind-lists.php) for vulnerabilities and software notifications.'
  desc 'fix', 'If BIND is utilized, the SA will subscribe to ISC’s mailing list called “bind-announce” (information on the Internet at http://www.isc.org/sw/bind/bind-lists.php) for vulnerabilities and software notifications.'
  impact 0.3
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-8508r1_chk'
  tag severity: 'low'
  tag gid: 'V-13052'
  tag rid: 'SV-13620r1_rule'
  tag stig_id: 'DNS0190'
  tag gtitle: 'SA has not subscribed to vendor mailing list.'
  tag fix_id: 'F-11675r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
