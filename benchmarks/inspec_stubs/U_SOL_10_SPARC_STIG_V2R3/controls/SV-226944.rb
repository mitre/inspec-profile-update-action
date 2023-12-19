control 'SV-226944' do
  title 'Mail relaying must be restricted.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending SPAM or other unauthorized activity.'
  desc 'check', %q(If the system uses Sendmail, locate the sendmail.cf file.
Procedure:
# find / -name sendmail.cf

Determine if Sendmail only binds to loopback addresses by examining the DaemonPortOptions configuration options.
Procedure:
# grep -i "O DaemonPortOptions" </path/to/sendmail.cf>

If there are uncommented DaemonPortOptions lines, and all such lines specify system loopback addresses, this is not a finding.

Otherwise, determine if Sendmail is configured to allow open relay operation.
Procedure:
# find / -name sendmail.mc
# grep -i promiscuous_relay </path/to/sendmail.mc>

If the promiscuous relay feature is enabled, this is a finding.

If the system uses Postfix, locate the main.cf file.
Procedure:
# find / -name main.cf

Determine if Postfix only binds to loopback addresses by examining the inet_interfaces line.
Procedure:
# grep inet_interfaces </path/to/main.cf>

If inet_interfaces is set to loopback-only or contains only loopback addresses, such as 127.0.0.1 and [::1], Postfix is not listening on external network interfaces, this is not a finding.

Otherwise, determine if Postfix is configured to restrict clients permitted to relay mail by examining the smtpd_client_restrictions line.
Procedure:
# grep smtpd_client_restrictions </path/to/main.cf>

If the smtpd_client_restrictions line is missing, or does not contain reject, this is a finding. If the line contains permit before reject, this is a finding. 

If the system is using other SMTP software, consult the software's documentation for procedures to verify mail relaying is restricted.)
  desc 'fix', %q(If the system uses Sendmail, edit the sendmail.mc file and remove the promiscuous_relay configuration. Rebuild the sendmail.cf file from the modified sendmail.mc and restart the service. If the system does not need to receive mail from external hosts, add one or more DaemonPortOptions lines referencing system loopback addresses (such as "O DaemonPortOptions=Addr=127.0.0.1,Port=smtp,Name=MTA") and remove lines containing non-loopback addresses. Restart the service.

If the system uses Postfix, edit the main.cf file and add or edit the smtpd_client_restrictions line to have contents permit mynetworks, reject or a similarly restrictive rule. If the system does not need to receive mail from external hosts, add or edit the inet_interfaces line to have contents loopback-only or a set of loopback addresses for the system. Restart the service.

If the system is using other SMTP software, consult the software's documentation for procedures to restrict mail relaying.)
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36411r602836_chk'
  tag severity: 'medium'
  tag gid: 'V-226944'
  tag rid: 'SV-226944r603265_rule'
  tag stig_id: 'GEN004710'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36375r602837_fix'
  tag 'documentable'
  tag legacy: ['SV-28908', 'V-23952']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
