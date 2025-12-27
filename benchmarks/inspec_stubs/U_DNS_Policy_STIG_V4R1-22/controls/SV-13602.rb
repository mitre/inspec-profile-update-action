control 'SV-13602' do
  title 'The DNS log archival requirements do not meet or exceed the log archival requirements of the operating system on which the DNS software resides.'
  desc 'Name servers are dedicated to the DNS function and, as a result, the most critical security and operations events on those name servers will appear in the DNS logs.  Different sites may have different policies regarding archival, but the DNS logs should be maintained in an equivalent (or better) manner as the operating system logs.  Therefore, if operating system logs are stored for a year, then DNS logs should be stored for at least a year.  If operating system logs are written to read-only media, then the DNS logs should be written to read-only media as well.'
  desc 'check', 'This check is only applicable if DNS logs are independent from system logs.  If the log archival scheme for the DNS logs is weaker than the one for the system logs, then this is a finding.This check is only applicable if DNS logs are independent from system logs.  If the log archival scheme for the DNS logs is weaker than the one for the system logs, then this is a finding.  

Windows

DNS log files are normally kept in two locations.  The system event logs which can be viewed from Event Viewer found under the Administrative tools from the Start Menu.  In addition, debug logging options such as query, notify, and update requirements can be viewed in a file named %systemroot%\\system32\\dns\\dns.log.

BIND

BIND logging files can be found by viewing the /etc/named.conf file.  Within the named.conf will be an option for logging that will display the file path to the log files.  In addition, most Unix machines will also log information in the syslog on the system.'
  desc 'fix', 'Working with appropriate technical and facility personnel, the IAO should implement an archival strategy that is at least as extensive as the current archival operation for operating system logs.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3355r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13034'
  tag rid: 'SV-13602r1_rule'
  tag stig_id: 'DNS0110'
  tag gtitle: 'The DNS log archival requirements are insufficient'
  tag fix_id: 'F-4338r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
